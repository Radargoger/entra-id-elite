"""
Botnet Data v2 fetcher.
Uses page + limit pagination with YYYY-MM-DD startDate (date string, not epoch).
Plaintext passwords expected -- sanitized immediately.
Client-side isEmployee filter (server-side not available).
"""

import os
import time
import logging
import requests
from datetime import datetime, timezone

from utils.sanitize import sanitize_password, build_law_password_fields
from sources.base_fetcher import BaseFetcher

ENDPOINT = "/api/company/{company_id}/dark-web-monitoring/botnet-data/v2"
PAGE_SIZE = 100


class BotnetFetcher(BaseFetcher):
    """Botnet-specific record mapping with employee filter and password sanitization."""

    def __init__(self):
        super().__init__(source_name="botnet", endpoint_template=ENDPOINT,
                         page_size=PAGE_SIZE)

    def _map_record(self, rec: dict, conf: dict) -> dict | None:
        # Client-side employee filter
        if not rec.get("isEmployee", False):
            return None

        pw_raw = rec.get("password")
        sanitized = sanitize_password(pw_raw)
        pw_fields = build_law_password_fields(sanitized)
        _raw = sanitized.pop("_raw", None)  # keep for ROPC only

        related = rec.get("relatedAlarm", {}) or {}
        entry = {
            "email":       rec.get("user", rec.get("email", "")),
            "url":         rec.get("url", ""),
            "device_ip":   rec.get("deviceIP", ""),
            "device_os":   rec.get("deviceOS", ""),
            "country":     rec.get("country", ""),
            "log_date":    rec.get("logDate", ""),
            "is_employee": True,
            "source":      "botnet",
            "alarm_id":    rec.get("alarmId") or related.get("alarmId"),
            **pw_fields,
        }

        # Preserve _raw for ROPC -- caller must del after use
        if _raw:
            entry["sanitized"] = {"is_plaintext": sanitized["is_plaintext"], "_raw": _raw}

        return entry


def fetch(conf: dict, checkpoint: dict, deadline: float = None,
          max_records: int = None) -> list:
    """
    Fetch Botnet Data v2 records.
    Filters to isEmployee=true on client side.
    Returns sanitized records (plaintext password never stored).
    Respects MAX_PAGES_PER_RUN to avoid function timeout.
    """
    return BotnetFetcher().fetch(conf, checkpoint, deadline, max_records)
