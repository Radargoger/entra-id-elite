"""
Mid-process manual former-employee entries.

Why this module exists: the timer reconcile (former_employee_sync) removes
anything on the SOCRadar list that the policy formula does not want. An analyst
manually adding someone (e.g. resignation announced, account not yet disabled)
would therefore be clobbered on the next tick. The fix is a persistent manual
set (Table FormerManual) that the sync unions into its desired set, so manual
entries survive reconciles until explicitly removed.

Exposed via the former_manual HTTP trigger in function_app.py:
  POST /api/former/manual   body: {"action": "add"|"remove", "emails": [...]}
"""

import re
import logging
from azure.data.tables import TableServiceClient, TableEntity
from azure.core.exceptions import ResourceNotFoundError, ResourceExistsError

from actions.socradar_former import _email_row_key

logger = logging.getLogger("socradar.elite.former_manual")

MANUAL_TABLE = "FormerManual"

# Practical email shape: single @, no whitespace/control chars, dotted domain.
# Also guards Table Storage RowKeys (control chars would make upsert fail).
_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
_MAX_EMAIL_LEN = 254


class ManualFormerStore:
    """Persistent set of manually-entered former emails (Table FormerManual)."""

    def __init__(self, storage_account_name: str, credential, company_id: str):
        url = f"https://{storage_account_name}.table.core.windows.net"
        service = TableServiceClient(endpoint=url, credential=credential)
        try:
            service.create_table(MANUAL_TABLE)
        except ResourceExistsError:
            pass
        self._table = service.get_table_client(MANUAL_TABLE)
        self._company = str(company_id)

    def get_set(self) -> set:
        emails = set()
        for entity in self._table.query_entities(f"PartitionKey eq '{self._company}'"):
            emails.add(str(entity.get("email", "")).lower())
        emails.discard("")
        return emails

    def add(self, emails: list) -> int:
        added = 0
        for email in emails:
            entity = TableEntity()
            entity["PartitionKey"] = self._company
            entity["RowKey"] = _email_row_key(email)
            entity["email"] = email
            self._table.upsert_entity(entity)
            added += 1
        return added

    def remove(self, emails: list) -> int:
        # Both key schemes on purpose: a row written before the hash change
        # must stay removable, or the union in the sync re-adds it forever.
        from actions.socradar_former import _delete_email_row
        removed = 0
        for email in emails:
            if _delete_email_row(self._table, self._company, email):
                removed += 1
        return removed


def apply_manual(action: str, emails: list, store, client) -> dict:
    """Manual former entry/removal (pure logic, HTTP-agnostic, unit-testable).

    add:    persist to the manual store (survives reconciles) AND push to the
            SOCRadar list immediately (no wait for the next timer tick).
            Store-first is deliberate: if the push fails, the next sync
            retries from the store (self-healing).
    remove: drop from the manual store AND push a removal. If the policy
            formula still wants this email former (own disabled / sibling
            active), the next sync re-adds it — policy beats a manual remove.
    """
    if action not in ("add", "remove"):
        raise ValueError(f"unknown action: {action}")

    clean, invalid = [], []
    seen = set()
    for raw in emails or []:
        email = str(raw).strip().lower()
        if len(email) > _MAX_EMAIL_LEN or not _EMAIL_RE.match(email):
            invalid.append(raw)
        elif email not in seen:
            seen.add(email)
            clean.append(email)

    result = {"action": action, "accepted": clean, "invalid": invalid, "stored": 0, "pushed": 0}
    if not clean:
        result["note"] = "no valid emails"
        return result

    if action == "add":
        result["stored"] = store.add(clean)
        result["pushed"] = client.add(clean, source="manual")
        if result["pushed"] < len(clean):
            # Never claim success the push did not earn (wrong actor email is
            # the typical cause). The store keeps the entries, so the next
            # timer sync retries the push automatically.
            result["note"] = (f"stored in manual store but SOCRadar push incomplete "
                              f"(pushed={result['pushed']}/{len(clean)}); next sync retries "
                              f"automatically — check FORMER_ACTOR_EMAIL / API errors")
        else:
            result["note"] = ("added to manual store and SOCRadar list; entries persist "
                              "across reconciles until removed via action=remove")
    else:
        result["stored"] = store.remove(clean)
        result["pushed"] = client.remove(clean)
        # "Removed from the SOCRadar list" would be a claim this code cannot
        # verify: the platform's delete route has been seen to answer 404 while
        # the record still exists, and its list endpoint answers data:null for
        # every path, so there is no readable confirmation either way.
        result["note"] = ("removed from manual store; removal pushed to SOCRadar, but this "
                          "platform cannot confirm deletions — verify in the platform UI. "
                          "If the policy formula still classifies an email as former, the "
                          "next sync re-adds it")

    logger.info("[FORMER-MANUAL] %s: accepted=%d invalid=%d stored=%d pushed=%d",
                action, len(clean), len(invalid), result["stored"], result["pushed"])
    return result
