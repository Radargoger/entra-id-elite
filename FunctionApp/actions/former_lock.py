"""
Per-company lease lock for the Former Employee sync (backlog P0: single
writer). The timer reconcile and the manual HTTP endpoint both mutate the same
SOCRadar list and ownership ledger; without a lock a manual add landing in the
middle of an apply-mode readback can corrupt the confirmed/owned accounting.

Table `FormerLock`, one row per company. Acquisition is optimistic-concurrency
(insert fails on an existing row; takeover of an EXPIRED lease replaces under
ETag). Leases carry a TTL so a crashed holder never wedges the company —
fail-open by expiry, never by force.

Callers:
  timer   — acquire per company; on conflict SKIP that company this tick
            (status LOCKED in the run table, next tick retries).
  manual  — acquire; on conflict return HTTP 409 (caller retries after the
            sync finishes).

Azure SDK imports are lazy (same pattern as the ownership store) so the pure
InMemory double and local test runs need no azure packages.
"""

import logging
from datetime import datetime, timezone, timedelta

logger = logging.getLogger("socradar.elite.former_lock")

LOCK_TABLE = "FormerLock"
DEFAULT_TTL_SECONDS = 300  # > one company reconcile, << a stuck-forever wedge


def _now():
    return datetime.now(timezone.utc)


class TableLeaseLock:
    """Lease on (company_id) with TTL."""

    def __init__(self, storage_account_name: str, credential, company_id: str,
                 holder: str, ttl_seconds: int = DEFAULT_TTL_SECONDS):
        from azure.data.tables import TableServiceClient
        from azure.core.exceptions import ResourceExistsError
        url = f"https://{storage_account_name}.table.core.windows.net"
        service = TableServiceClient(endpoint=url, credential=credential)
        try:
            service.create_table(LOCK_TABLE)
        except ResourceExistsError:
            pass
        self._table = service.get_table_client(LOCK_TABLE)
        self._company = str(company_id)
        self._holder = holder
        self._ttl = ttl_seconds
        self._held = False

    def _entity(self):
        from azure.data.tables import TableEntity
        e = TableEntity()
        e["PartitionKey"] = "lock"
        e["RowKey"] = self._company
        e["holder"] = self._holder
        e["expires_at"] = (_now() + timedelta(seconds=self._ttl)).isoformat()
        return e

    def acquire(self) -> bool:
        from azure.core import MatchConditions
        from azure.data.tables import UpdateMode
        from azure.core.exceptions import ResourceExistsError
        try:
            self._table.create_entity(self._entity())
            self._held = True
            return True
        except ResourceExistsError:
            pass
        # Row exists: take over ONLY an expired lease, under ETag so two
        # takeover attempts cannot both win.
        try:
            current = self._table.get_entity(partition_key="lock", row_key=self._company)
            expires = str(current.get("expires_at") or "")
            if expires and expires > _now().isoformat():
                logger.info("[FORMER-LOCK] company %s held by %s until %s",
                            self._company, current.get("holder"), expires)
                return False
            self._table.update_entity(
                self._entity(), mode=UpdateMode.REPLACE,
                etag=current.metadata["etag"],
                match_condition=MatchConditions.IfNotModified)
            self._held = True
            return True
        except Exception as e:
            # Lost the race (row deleted/replaced between read and write) —
            # treat as not acquired, never crash a sync over a lock.
            logger.info("[FORMER-LOCK] company %s takeover failed (%s)",
                        self._company, type(e).__name__)
            return False

    def release(self) -> None:
        if not self._held:
            return
        try:
            from azure.core import MatchConditions
            current = self._table.get_entity(partition_key="lock", row_key=self._company)
            if current.get("holder") == self._holder:
                # ETag-conditional delete: if another party took over our
                # EXPIRED lease between the get and this delete (TOCTOU), the
                # ETag no longer matches and their fresh lease survives.
                self._table.delete_entity(
                    partition_key="lock", row_key=self._company,
                    etag=current.metadata["etag"],
                    match_condition=MatchConditions.IfNotModified)
        except Exception as e:  # release is best-effort; expiry is the backstop
            logger.info("[FORMER-LOCK] release skipped for %s: %s", self._company, e)
        self._held = False


class InMemoryLeaseLock:
    """Test double with the same surface."""

    _locks = {}

    def __init__(self, company_id: str, holder: str, ttl_seconds: int = DEFAULT_TTL_SECONDS):
        self._company = str(company_id)
        self._holder = holder
        self._ttl = ttl_seconds
        self._held = False

    def acquire(self) -> bool:
        entry = InMemoryLeaseLock._locks.get(self._company)
        if entry and entry["expires_at"] > _now():
            return False
        InMemoryLeaseLock._locks[self._company] = {
            "holder": self._holder,
            "expires_at": _now() + timedelta(seconds=self._ttl)}
        self._held = True
        return True

    def release(self) -> None:
        entry = InMemoryLeaseLock._locks.get(self._company)
        if self._held and entry and entry["holder"] == self._holder:
            del InMemoryLeaseLock._locks[self._company]
        self._held = False
