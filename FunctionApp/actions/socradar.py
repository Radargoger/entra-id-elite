"""
SOCRadar Platform API — alarm status update.
Resolves alarms when compromised users are found in Entra ID.
"""

import logging
import requests

logger = logging.getLogger("socradar.entra.socradar_api")

STATUS_ENDPOINT = "/api/company/{company_id}/alarms/status/change"

# SOCRadar alarm statuses
STATUS_RESOLVED = 2
STATUS_FALSE_POSITIVE = 9
STATUS_MITIGATED = 12


def resolve_alarm(api_key: str, company_id: str, alarm_id: int, comment: str = "", base_url: str = "https://platform.socradar.com") -> bool:
    """
    Resolve a SOCRadar alarm by setting status to RESOLVED (2).

    Returns True on success, False on failure.
    """
    if not alarm_id:
        return False

    url = base_url + STATUS_ENDPOINT.format(company_id=company_id)
    headers = {
        "API-Key": api_key,
        "Content-Type": "application/json",
    }
    body = {
        "alarm_ids": [int(alarm_id)],
        "status": STATUS_RESOLVED,
    }
    if comment:
        body["comments"] = comment

    try:
        resp = requests.post(url, json=body, headers=headers, timeout=15)
        if resp.status_code == 200 and resp.json().get("is_success"):
            logger.info("[SOCRADAR] Alarm %s resolved", alarm_id)
            return True
        logger.error("[SOCRADAR] Alarm %s resolve failed: %d — %s", alarm_id, resp.status_code, resp.text[:200])
        return False
    except requests.RequestException as e:
        logger.error("[SOCRADAR] Alarm %s resolve error: %s", alarm_id, e)
        return False
