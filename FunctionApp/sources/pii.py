"""
PII Exposure v2 fetcher.
Uses page + limit pagination with YYYY-MM-DD startDate (date string, not epoch).
Mixed passwords (some masked, some plaintext) — always sanitize.
"""

import os
import time
import logging
import requests
from datetime import datetime, timezone

from utils.logger import get_logger
from utils.sanitize import sanitize_password, build_law_password_fields
from utils.checkpoint import get_start_date

logger = get_logger("pii")

ENDPOINT = "/api/company/{company_id}/dark-web-monitoring/pii-exposure/v2"
PAGE_SIZE = 100

MAX_PAGES_PER_RUN = int(os.environ.get("MAX_PAGES_PER_RUN", "50"))


def fetch(conf: dict, checkpoint: dict) -> list:
    """
    Fetch PII Exposure v2 records.
    isEmployee filter applied client-side if field present.
    Returns sanitized records.
    Respects MAX_PAGES_PER_RUN to avoid function timeout.
    """
    api_key = conf["socradar_api_key"]
    company_id = conf["socradar_company_id"]
    enable_log_plaintext = conf.get("enable_log_plaintext_password", False)
    initial_lookback = conf.get("initial_lookback_minutes", 600)
    initial_start_date = conf.get("initial_start_date", "")

    base = conf.get("socradar_base_url", "https://platform.socradar.com")
    url = base + ENDPOINT.format(company_id=company_id)
    headers = {
        "API-Key": api_key,
        "Content-Type": "application/json",
        "User-Agent": "SOCRadar-EntraID/1.0",
    }

    start_date = get_start_date(checkpoint, initial_lookback, initial_start_date)
    resume_page = checkpoint.get("last_page", 0)
    logger.info("[PII] Starting fetch. start_date=%s, page=%d", start_date, resume_page + 1)

    all_records = []
    page = resume_page + 1 if resume_page else 1
    # Init total_pages so the first loop iteration always runs (real value
    # comes from the first API response). Using 1 here breaks resume: if
    # resume_page=100 then page=101 and `page <= total_pages` is False, the
    # loop never executes, and `finished_all` becomes True erroneously —
    # checkpoint advances to today and the remaining backlog is lost.
    total_pages = page
    total_data_count = None
    pages_this_run = 0

    while page <= total_pages and pages_this_run < MAX_PAGES_PER_RUN:
        params = {
            "page": page,
            "limit": PAGE_SIZE,
            "startDate": start_date,
        }

        try:
            resp = requests.get(url, headers=headers, params=params, timeout=30)
        except requests.RequestException as e:
            logger.error(f"Request failed on page {page}: {e}")
            break

        if resp.status_code != 200:
            logger.error(f"API error {resp.status_code} on page {page}: {resp.text[:200]}")
            break

        data = resp.json()
        if not data.get("is_success"):
            logger.error(f"API returned is_success=false: {data.get('message', 'unknown')}")
            break

        payload = data.get("data", {})
        records_raw = payload.get("data", [])

        if total_data_count is None:
            total_data_count = payload.get("total_data_count", 0)
            total_pages = max(1, -(-total_data_count // PAGE_SIZE))
            logger.info(f"Total records={total_data_count}, pages={total_pages}")

        employees_this_page = 0

        for rec in records_raw:
            # PII may have isEmployee field — filter if present and false
            if "isEmployee" in rec and not rec["isEmployee"]:
                continue

            pw_raw = rec.get("password")
            sanitized = sanitize_password(pw_raw)
            pw_fields = build_law_password_fields(sanitized, enable_log_plaintext)
            _raw = sanitized.pop("_raw", None)

            # source field is array in PII API
            source_val = rec.get("source", "")
            if isinstance(source_val, list):
                source_val = ", ".join(source_val)

            related = rec.get("relatedAlarm", {}) or {}
            entry = {
                "email":          rec.get("email", ""),
                "source_name":    source_val,
                "breach_date":    rec.get("breachDate", ""),
                "discovery_date": rec.get("discoveryDate", ""),
                "is_employee":    rec.get("isEmployee", True),
                "source":         "pii",
                "alarm_id":       rec.get("alarmId") or related.get("alarmId"),
                **pw_fields,
            }

            if _raw:
                entry["sanitized"] = {"is_plaintext": sanitized.get("is_plaintext", False), "_raw": _raw}

            all_records.append(entry)
            employees_this_page += 1

        logger.fetch_page(
            page=page,
            total_pages=total_pages,
            records=len(records_raw),
            employees=employees_this_page
        )

        if not records_raw:
            break

        pages_this_run += 1
        page += 1
        time.sleep(1)

    logger.fetch_done(total=total_data_count or 0, employees=len(all_records))

    finished_all = page > total_pages
    today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    checkpoint_update = {
        "last_start_date": today_str if finished_all else start_date,
        "last_page": 0 if finished_all else page - 1,
    }

    if not finished_all:
        logger.info("[PII] Paused at page %d/%d (limit %d/run). Will resume next run.",
                     page - 1, total_pages, MAX_PAGES_PER_RUN)

    if all_records:
        all_records[-1]["_checkpoint_update"] = checkpoint_update
    else:
        all_records.append({"_checkpoint_update": checkpoint_update, "_empty_marker": True})

    return all_records
