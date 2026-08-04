"""
Table Storage checkpoint management.
Supports checkpoint_date and standard sources (date string + page).

startDate format: YYYY-MM-DD (date string as expected by SOCRadar API).
"""

import time
import logging
from datetime import datetime, timezone, timedelta
from azure.data.tables import TableServiceClient, TableEntity
from azure.core.exceptions import ResourceNotFoundError

logger = logging.getLogger("socradar.entra.checkpoint")

TABLE_NAME = "EntraIDState"


def _get_table(storage_account_name: str, credential):
    url = f"https://{storage_account_name}.table.core.windows.net"
    return TableServiceClient(
        endpoint=url, credential=credential
    ).get_table_client(TABLE_NAME)


def load(storage_account_name: str, credential, source: str) -> dict:
    """
    Load checkpoint for a given source.

    Returns dict with source-specific fields, or empty dict if no checkpoint exists.
    """
    client = _get_table(storage_account_name, credential)
    try:
        entity = client.get_entity(partition_key=source, row_key="checkpoint")
        return dict(entity)
    except ResourceNotFoundError:
        logger.info("[CHECKPOINT] No existing checkpoint for source=%s", source)
        return {}


def save(storage_account_name: str, credential, source: str, data: dict):
    """
    Save checkpoint for a given source.

    data should contain source-specific fields (no PartitionKey/RowKey needed).
    """
    url = f"https://{storage_account_name}.table.core.windows.net"
    service = TableServiceClient(endpoint=url, credential=credential)
    try:
        service.create_table_if_not_exists(TABLE_NAME)  # greenfield: table may not exist yet
    except Exception as e:
        # Benign on races; a genuinely broken table/credential surfaces loudly
        # at the upsert below — but keep the diagnostic signal.
        logger.info("[CHECKPOINT] table ensure skipped: %s", e)
    client = service.get_table_client(TABLE_NAME)
    entity = TableEntity()
    entity["PartitionKey"] = source
    entity["RowKey"] = "checkpoint"
    entity["last_run_epoch"] = int(time.time())
    for k, v in data.items():
        if k not in ("PartitionKey", "RowKey"):
            entity[k] = v
    client.upsert_entity(entity)
    logger.info("[CHECKPOINT] Saved for source=%s: %s", source, data)


def get_start_date(checkpoint: dict, initial_lookback_minutes: int, initial_start_date: str = "") -> str:
    """
    Return the startDate string (YYYY-MM-DD) for a fetch cycle.

    SOCRadar API expects date string format, not epoch time.

    Priority:
      1. Existing checkpoint last_start_date (resume from where we left off)
      2. active_window_start — a window a previous run opened and did not finish
      3. InitialStartDate parameter (customer-specified date, e.g. "2025-06-15")
      4. Calculated from InitialLookbackMinutes (now - N minutes)

    Step 2 exists because step 4 moves. A run that holds its window records no
    last_start_date, so the next run recomputed the start from the lookback and
    landed a day later. The window shifted, and the idempotency key derived from
    it shifted with it: the ledger no longer recognised a repeat, and someone
    already acted on could be acted on a second time — including by the actions
    that cannot be undone.
    """
    if checkpoint.get("last_start_date"):
        return str(checkpoint["last_start_date"])
    if checkpoint.get("active_window_start"):
        return str(checkpoint["active_window_start"])
    if initial_start_date:
        return str(initial_start_date)
    lookback_dt = datetime.now(timezone.utc) - timedelta(minutes=initial_lookback_minutes)
    return lookback_dt.strftime("%Y-%m-%d")
