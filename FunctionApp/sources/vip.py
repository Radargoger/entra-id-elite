"""
VIP Protection v2 fetcher.
No password field in responses. Entra ID actions limited to lookup + incident.
"""

import os
import time
import logging
import requests
from datetime import datetime, timezone

from sources.base_fetcher import BaseFetcher

ENDPOINT = "/api/company/{company_id}/vip-protection/v2"
PAGE_SIZE = 100


class VipFetcher(BaseFetcher):
    """VIP-specific record mapping (no passwords, no employee filter)."""

    def __init__(self):
        super().__init__(source_name="vip", endpoint_template=ENDPOINT,
                         page_size=PAGE_SIZE)

    def _validate_response(self, resp, page: int) -> bool:
        if resp.status_code == 404:
            self.logger.error(
                "VIP endpoint returned 404 -- endpoint may not exist for this company"
            )
            return False
        return super()._validate_response(resp, page)

    @staticmethod
    def _address(rec: dict) -> str:
        """Pick the field that actually carries an address, or return nothing.

        vipName is a display name, not an address, and a VIP record need not
        carry an address field at all. Reading vipName as the address sent
        "Firstname Lastname" to Graph, which answers 404 the same way it answers
        for an address nobody has heard of — so the run recorded clean misses it
        could never have avoided. The okta and Google connectors already choose
        the first candidate that holds an address; this is that rule, brought
        over.

        When no field holds one, say so by returning "" rather than falling
        back to the display name. There is nothing to look up, and asking Graph
        about a person's name only manufactures a miss that looks like an answer.

        Do not widen this to `history`. Addresses do appear there, but they sit
        in the `operator` field, which names the analyst who handled the record,
        not the person the record is about. Treating them as the subject's
        address would point the lookup, and any armed response, at the wrong
        human being.
        """
        for candidate in (rec.get("vipName"), rec.get("email"), rec.get("keyword")):
            addr = str(candidate).strip() if candidate else ""
            # Containing an '@' is not the same as being an address. `keyword`
            # is free text and holds things like "creds for a@b.com on sale":
            # sending that to Graph asks about a person who does not exist and
            # files the answer as a clean miss. Take it only when the whole
            # value is one address.
            if addr.count("@") == 1 and not any(c.isspace() for c in addr):
                local, _, domain = addr.partition("@")
                if local and "." in domain:
                    return addr
        return ""

    def _map_record(self, rec: dict, conf: dict) -> dict | None:
        related = rec.get("relatedAlarm", {}) or {}
        return {
            "email":          self._address(rec),
            "keyword":        rec.get("keyword", ""),
            "vip_name":       rec.get("vipName", ""),
            "status":         rec.get("status", ""),
            "discovery_date": rec.get("discoveryDate", ""),
            "source_name":    rec.get("source", ""),
            "is_employee":    True,
            "source":         "vip",
            "alarm_id":       rec.get("alarmId") or related.get("alarmId"),
            # No password field in VIP responses
            "password_present": False,
            "password_masked":  None,
            "is_plaintext":     False,
        }


def fetch(conf: dict, checkpoint: dict, deadline: float = None,
          max_records: int = None) -> list:
    """
    Fetch VIP Protection v2 records.
    Respects MAX_PAGES_PER_RUN to avoid function timeout.
    """
    return VipFetcher().fetch(conf, checkpoint, deadline, max_records)
