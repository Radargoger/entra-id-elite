"""
Idempotency ledger for leak-source actions (code-review finding B1).

Prevents duplicate remediation actions when the same leak window is re-read
(e.g. checkpoint re-reads the same window after a partial run, or a held
checkpoint retries the same batch). Without this, the same user gets
revoke_session / force_password_change / etc. applied repeatedly.

Key design: PartitionKey = "{source}:{company_id}",
            RowKey       = sha256("{email}:{action}:{window_date}")

The raw email is never stored (PII — same rule as former_ownership.py).

Two implementations:
  - InMemoryActionLedger: for unit tests and plan-only mode (no storage).
  - ActionLedger:         Azure Table ``LeakActionLedger``
                          (lazy Azure SDK imports so unit tests need no SDK).
"""

import hashlib
import logging
from datetime import datetime, timedelta, timezone

logger = logging.getLogger("socradar.elite.action_ledger")

LEDGER_TABLE = "LeakActionLedger"

# Ordinary runs read a window of at most 24h, and a held window is retried a
# few times, so thirty days is far beyond anything a repeat can reach back to.
# It is NOT the whole protection: a first run may look back as far as
# LeakInitialLookbackDays, and the portal form offers 365. That window sits
# outside any fixed floor, and it is covered by clamping to the window in
# flight rather than by this number.
MIN_RETENTION_DAYS = 30


def _row_key(email: str, action: str, window_date: str) -> str:
    """Privacy-preserving composite key — never stores the raw email."""
    raw = f"{str(email).strip().lower()}:{action}:{window_date}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def cutoff_date(retention_days, today=None, active_window=None) -> str:
    """Oldest window worth remembering, as YYYY-MM-DD.

    Three things decide the answer, and dropping any one of them lets the
    ledger delete a row that still has work to do, which means the same person
    is acted on twice.

    Floored at MIN_RETENTION_DAYS, so a retention of 0 entered by mistake
    cannot purge the window being processed.

    Clamped to ``active_window`` when the caller knows which window is in
    flight. A first run with a 365-day lookback stamps its rows a year back,
    older than any sane retention, so an unclamped cutoff would delete the
    idempotency records of the very run writing them, on the largest batch the
    deployment will ever handle.

    UTC, not the host clock. The window dates this is compared against are
    themselves built from UTC (sources/base_fetcher, utils/checkpoint), so a
    local-time cutoff would sit a day away from the values it filters on.
    """
    try:
        days = int(retention_days)
    except (TypeError, ValueError):
        days = MIN_RETENTION_DAYS
    days = max(MIN_RETENTION_DAYS, days)
    today = today or datetime.now(timezone.utc).date()
    cutoff = (today - timedelta(days=days)).strftime("%Y-%m-%d")
    if active_window:
        # purge_before deletes strictly older rows, so a cutoff equal to the
        # active window leaves that window's own records alone.
        return min(cutoff, str(active_window))
    return cutoff


class InMemoryActionLedger:
    """Non-persistent ledger for tests and plan-only mode."""

    def __init__(self):
        # key -> window_date, so purge_before behaves the same way here as it
        # does against the table.
        self._seen = {}

    def already_applied(self, email: str, source: str, action: str,
                        window_date: str) -> bool:
        key = _row_key(email, action, window_date)
        return key in self._seen

    def record_applied(self, email: str, source: str, action: str,
                       window_date: str) -> None:
        key = _row_key(email, action, window_date)
        self._seen[key] = window_date

    def purge_before(self, cutoff: str, max_rows: int = 500) -> int:
        stale = [k for k, d in self._seen.items() if d < cutoff][:max_rows]
        for key in stale:
            del self._seen[key]
        return len(stale)


class ActionLedger:
    """Azure Table backed idempotency ledger. RowKey = sha256(email:action:date);
    the raw address is never stored (PII). Import kept lazy so unit tests
    need no SDK."""

    def __init__(self, storage_account_name: str, credential,
                 source: str, company_id: str):
        from azure.data.tables import TableServiceClient
        from azure.core.exceptions import ResourceExistsError

        url = f"https://{storage_account_name}.table.core.windows.net"
        service = TableServiceClient(endpoint=url, credential=credential)
        try:
            service.create_table(LEDGER_TABLE)
        except ResourceExistsError:
            pass
        self._table = service.get_table_client(LEDGER_TABLE)
        self._partition = f"{source}:{company_id}"

    def already_applied(self, email: str, source: str, action: str,
                        window_date: str) -> bool:
        from azure.core.exceptions import ResourceNotFoundError
        rk = _row_key(email, action, window_date)
        try:
            self._table.get_entity(self._partition, rk)
            return True
        except ResourceNotFoundError:
            return False

    def record_applied(self, email: str, source: str, action: str,
                       window_date: str) -> None:
        from azure.data.tables import TableEntity
        entity = TableEntity()
        entity["PartitionKey"] = self._partition
        entity["RowKey"] = _row_key(email, action, window_date)
        entity["action"] = action
        entity["window_date"] = window_date
        self._table.upsert_entity(entity)

    def purge_before(self, cutoff: str, max_rows: int = 500) -> int:
        """Drop rows whose window is older than ``cutoff`` (YYYY-MM-DD).

        Bounded on purpose: a deployment that has been running for a year has
        a large backlog, and draining it over several runs costs nothing,
        while draining it in one would eat the run's time slot. Returns how
        many rows were removed.
        """
        from azure.core.exceptions import ResourceNotFoundError
        query = (f"PartitionKey eq '{self._partition}' "
                 f"and window_date lt '{cutoff}'")
        deleted = 0
        for entity in self._table.query_entities(
                query, select=["PartitionKey", "RowKey"]):
            if deleted >= max_rows:
                break
            try:
                self._table.delete_entity(entity["PartitionKey"],
                                          entity["RowKey"])
                deleted += 1
            except ResourceNotFoundError:
                # Another run removed it first. Nothing to do.
                pass
        return deleted
