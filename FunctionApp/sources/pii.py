"""
PII Exposure v2 fetcher.
Uses page + limit pagination with YYYY-MM-DD startDate (date string, not epoch).
Mixed passwords (some masked, some plaintext) -- always sanitize.
"""

import os
import time
import logging
import requests
from datetime import datetime, timezone

from utils.sanitize import sanitize_password, build_law_password_fields
from sources.base_fetcher import BaseFetcher

ENDPOINT = "/api/company/{company_id}/dark-web-monitoring/pii-exposure/v2"
PAGE_SIZE = 100


class PiiFetcher(BaseFetcher):
    """PII-specific record mapping with optional employee filter and password sanitization."""

    def __init__(self):
        super().__init__(source_name="pii", endpoint_template=ENDPOINT,
                         page_size=PAGE_SIZE)

    def _map_record(self, rec: dict, conf: dict) -> dict | None:
        # PII may have isEmployee field -- filter if present and false
        if "isEmployee" in rec and not rec["isEmployee"]:
            return None

        pw_raw = rec.get("password")
        sanitized = sanitize_password(pw_raw)
        pw_fields = build_law_password_fields(sanitized)
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

        return entry


def fetch(conf: dict, checkpoint: dict, deadline: float = None,
          max_records: int = None) -> list:
    """
    Fetch PII Exposure v2 records.
    isEmployee filter applied client-side if field present.
    Returns sanitized records.
    Respects MAX_PAGES_PER_RUN to avoid function timeout.
    """
    return PiiFetcher().fetch(conf, checkpoint, deadline, max_records)
