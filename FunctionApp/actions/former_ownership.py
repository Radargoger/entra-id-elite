"""
Ownership ledger for the Former Employee sync (PRODUCTION-HARDENING-BACKLOG P0).

Records which emails on the SOCRadar former list Elite created and confirmed,
so the reconcile planner can distinguish OUR records (removal candidates) from
EXTERNAL records added by the UI or another integration (always preserved).

Privacy (backlog P0 rule 8, PII): the ledger stores sha256(normalized email),
never the raw address. Membership queries hash the caller's emails and compare,
so the raw list never has to be persisted here.

State machine (a subset of the backlog states, enough to gate deletion safely):

    (absent) --add confirmed--> owned --remove confirmed--> tombstone
       ^                                                        |
       +--------------------- re-add confirmed ------------------

`external` is implicit: any email in `current` whose hash is not `owned` is
external and is never a removal candidate.

Two implementations:
  - InMemoryOwnershipStore: for unit tests and plan-only runs without storage.
  - TableOwnershipStore:     Azure Table `FormerOwnership`
                             (PartitionKey = company id, RowKey = sha256(email)).
"""

import hashlib
import logging

logger = logging.getLogger("socradar.elite.former_ownership")

OWNERSHIP_TABLE = "FormerOwnership"

STATE_OWNED = "owned"
STATE_TOMBSTONE = "tombstone"


def email_hash(email: str) -> str:
    return hashlib.sha256(str(email).strip().lower().encode("utf-8")).hexdigest()


class InMemoryOwnershipStore:
    """Non-persistent ownership ledger for tests and plan-only mode."""

    def __init__(self, seed_owned=None):
        # hash -> state
        self._states = {}
        for email in seed_owned or []:
            self._states[email_hash(email)] = STATE_OWNED

    def is_bootstrap(self) -> bool:
        """True when the ledger has never recorded anything for this company."""
        return not self._states

    def owned_among(self, emails) -> set:
        """Subset of `emails` whose hash is currently state=owned."""
        out = set()
        for email in emails or []:
            if self._states.get(email_hash(email)) == STATE_OWNED:
                out.add(email)
        return out

    def mark_owned(self, emails) -> int:
        count = 0
        for email in emails or []:
            self._states[email_hash(email)] = STATE_OWNED
            count += 1
        return count

    def mark_tombstone(self, emails) -> int:
        count = 0
        for email in emails or []:
            self._states[email_hash(email)] = STATE_TOMBSTONE
            count += 1
        return count


class TableOwnershipStore:
    """Azure Table backed ownership ledger. RowKey = sha256(email); the raw
    address is never stored (PII). Import kept lazy so unit tests need no SDK."""

    def __init__(self, storage_account_name: str, credential, company_id: str):
        from azure.data.tables import TableServiceClient
        from azure.core.exceptions import ResourceExistsError

        url = f"https://{storage_account_name}.table.core.windows.net"
        service = TableServiceClient(endpoint=url, credential=credential)
        try:
            service.create_table(OWNERSHIP_TABLE)
        except ResourceExistsError:
            pass
        self._table = service.get_table_client(OWNERSHIP_TABLE)
        self._company = str(company_id)

    def _query(self):
        return self._table.query_entities(f"PartitionKey eq '{self._company}'")

    def is_bootstrap(self) -> bool:
        for _ in self._query():
            return False
        return True

    def owned_among(self, emails) -> set:
        from azure.core.exceptions import ResourceNotFoundError
        out = set()
        for email in emails or []:
            try:
                entity = self._table.get_entity(self._company, email_hash(email))
            except ResourceNotFoundError:
                continue
            if str(entity.get("state", "")) == STATE_OWNED:
                out.add(email)
        return out

    def _set_state(self, emails, state) -> int:
        from azure.data.tables import TableEntity
        count = 0
        for email in emails or []:
            entity = TableEntity()
            entity["PartitionKey"] = self._company
            entity["RowKey"] = email_hash(email)
            entity["state"] = state
            self._table.upsert_entity(entity)
            count += 1
        return count

    def mark_owned(self, emails) -> int:
        return self._set_state(emails, STATE_OWNED)

    def mark_tombstone(self, emails) -> int:
        return self._set_state(emails, STATE_TOMBSTONE)
