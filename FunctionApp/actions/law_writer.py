"""
Log Analytics Workspace (LAW) writer via Azure Monitor Logs Ingestion API (DCR-based).
Replaces the legacy HTTP Data Collector API (deprecated 2026-09-14).

Migration notes:
- Old: HMAC-SHA256 signed POST to ods.opinsights.azure.com/api/logs
- New: OAuth Bearer token via UAMI/DefaultAzureCredential, POST to DCR endpoint
- Auth: Monitoring Metrics Publisher role on the DCR scope (assigned to UAMI)
- Schema: explicit per-table column declarations in DCR streamDeclarations

Credential policy: the value is stored as the feed delivered it, masked or
clear, and the table declares a column for it. Masking is chosen per company
inside SOCRadar; there is no application-side switch. See docs/product-policy.md §2.
"""

import logging
from datetime import datetime, timezone

from azure.identity import DefaultAzureCredential
from azure.monitor.ingestion import LogsIngestionClient
from azure.core.exceptions import HttpResponseError

logger = logging.getLogger("socradar.entra.law")

# Stream name = "Custom-<TableName>_CL" (must match DCR streamDeclarations)
STREAM_MAP = {
    "botnet": "Custom-SOCRadar_Botnet_CL",
    "pii":    "Custom-SOCRadar_PII_CL",
    "vip":    "Custom-SOCRadar_VIP_CL",
}
AUDIT_STREAM = "Custom-SOCRadar_EntraID_Audit_CL"
IMPORT_AUDIT_STREAM = "Custom-SOCRadar_ImportAudit_CL"

BATCH_SIZE = 1000  # Logs Ingestion API allows up to 1MB per call; 1000 records is safe default
MAX_FIELD_LEN = 30000

# Singleton client, re-used across invocations, held as one (endpoint, client)
# pair. Two separate globals cannot be published together, and the same shape
# in actions/entra_id.py let one company's run pick up another company's Graph
# credential. Nothing that bad is reachable here (there is a single
# DCR_ENDPOINT, and the credential is not tenant-scoped), but the shape is the
# defect, and leaving one copy of it invites the next one.
_client: tuple | None = None


def _get_client(endpoint: str) -> LogsIngestionClient | None:
    """Return cached LogsIngestionClient or build one with DefaultAzureCredential."""
    global _client
    cached = _client
    if cached is not None and cached[0] == endpoint:
        return cached[1]
    try:
        credential = DefaultAzureCredential()
        client = LogsIngestionClient(endpoint=endpoint, credential=credential)
        _client = (endpoint, client)
        logger.info("[LAW] LogsIngestionClient initialized for %s", endpoint)
        return client
    except Exception as e:
        logger.error("[LAW] Failed to initialize LogsIngestionClient: %s", e)
        return None


def _upload(rule_id: str, stream_name: str, records: list, endpoint: str) -> bool:
    """Upload a batch of records to a DCR stream. Returns True on success."""
    client = _get_client(endpoint)
    if client is None:
        return False
    try:
        client.upload(rule_id=rule_id, stream_name=stream_name, logs=records)
        logger.info("[LAW] %s: %d records uploaded", stream_name, len(records))
        return True
    except HttpResponseError as e:
        logger.error("[LAW] %s upload failed: HTTP %s — %s", stream_name, e.status_code, str(e)[:300])
        return False
    except Exception as e:
        logger.error("[LAW] %s upload error: %s", stream_name, e)
        return False


def _clean_record(rec: dict) -> dict:
    """Remove internal-only fields, truncate long strings, add TimeGenerated.

    The credential itself is written as the feed delivered it: masked or clear
    is decided per company in the SOCRadar platform, upstream of this app.
    """
    out = {}
    # entra_user_id used to be dropped here, alongside genuinely internal
    # plumbing. Nothing chose that: the object ID is the only field that lets a
    # customer line a row up against Microsoft Entra ID's own audit log and
    # confirm from an independent source that a change the app reports actually
    # happened. It is declared in the collection rule, so it lands.
    skip_keys = {"_checkpoint_update", "sanitized", "_empty_marker"}
    for k, v in rec.items():
        if k in skip_keys:
            continue
        if isinstance(v, str) and len(v) > MAX_FIELD_LEN:
            v = v[:MAX_FIELD_LEN] + "...[truncated]"
        out[k] = v
    # TimeGenerated is required by DCR
    out.setdefault("TimeGenerated", datetime.now(timezone.utc).isoformat())
    return out


def write_records(conf: dict, source_name: str, records: list) -> bool:
    """Write source records to the matching LAW table in batches.

    Returns whether every batch landed. The caller holds the checkpoint back on
    a failure, otherwise the records are lost: the window is never read again.
    """
    stream_name = STREAM_MAP.get(source_name)
    if not stream_name:
        logger.warning("[LAW] Unknown source: %s — skipping", source_name)
        return False

    rule_id = conf.get("dcr_immutable_id")
    endpoint = conf.get("dcr_endpoint")
    if not rule_id or not endpoint:
        logger.error("[LAW] DCR_IMMUTABLE_ID or DCR_ENDPOINT missing — cannot write %s records", source_name)
        return False

    cleaned = [_clean_record(r) for r in records]

    # One deployment serves several companies, so a finding that cannot be
    # attributed to one of them is not actionable.
    company_id = str(conf.get("socradar_company_id", ""))
    for record in cleaned:
        record.setdefault("company_id", company_id)

    ok = True
    for i in range(0, len(cleaned), BATCH_SIZE):
        batch = cleaned[i:i + BATCH_SIZE]
        ok = _upload(rule_id, stream_name, batch, endpoint) and ok
    return ok


def write_lifecycle_event(conf: dict, event_type: str, tenant_id: str = "", details: str = "", extra: dict = None):
    """
    Write a single lifecycle/operational event to SOCRadar_EntraID_Audit_CL.
    Intended for events like consent_revoked, token_failure, permission_denied.
    """
    rule_id = conf.get("dcr_immutable_id")
    endpoint = conf.get("dcr_endpoint")
    if not rule_id or not endpoint:
        logger.warning("[LAW] lifecycle event %s skipped — DCR not configured", event_type)
        return False

    record = {
        "TimeGenerated": datetime.now(timezone.utc).isoformat(),
        "source":     "lifecycle",
        "event_type": event_type,
        # Without this the row lands with an empty company, so a per-company
        # query over the audit table silently skips every lifecycle event —
        # the failures, in a multi-company deployment, of exactly the company
        # somebody is investigating.
        "company_id": str(conf.get("socradar_company_id", "")),
        "tenant_id":  tenant_id,
        "details":    details[:1000] if details else "",
    }
    if extra:
        for k, v in extra.items():
            record.setdefault(k, v)
    return _upload(rule_id, AUDIT_STREAM, [record], endpoint)


def write_former_audit(conf: dict, rows: list) -> bool:
    """Upload former-sync audit rows (built by actions/former_audit.py, hashed
    emails only) to SOCRadar_EntraID_Audit_CL. No DCR configured => skip."""
    rule_id = conf.get("dcr_immutable_id")
    endpoint = conf.get("dcr_endpoint")
    if not rule_id or not endpoint:
        logger.info("[LAW] former audit skipped — DCR not configured")
        return False
    ok = True
    for i in range(0, len(rows), BATCH_SIZE):
        ok = _upload(rule_id, AUDIT_STREAM, rows[i:i + BATCH_SIZE], endpoint) and ok
    return ok


def write_audit(conf: dict, audit_results: list):
    """Write import run summaries to SOCRadar_ImportAudit_CL.

    These fields do not exist in the former-sync audit schema, and a stream that
    does not declare a column drops it without reporting an error — so the two
    summaries need their own tables rather than a shared one.
    """
    rule_id = conf.get("dcr_immutable_id")
    endpoint = conf.get("dcr_endpoint")
    if not rule_id or not endpoint:
        logger.warning("[LAW] audit summary skipped — DCR not configured")
        return False

    ts = datetime.now(timezone.utc).isoformat()
    records = []
    for r in audit_results:
        records.append({
            "TimeGenerated":    ts,
            "source":           r.get("source", ""),
            "company_id":       str(r.get("company_id", "")),
            "total_records":    r.get("total", 0),
            "employee_records": r.get("employees", 0),
            "found_count":      r.get("found", 0),
            "not_found_count":  r.get("not_found", 0),
            "actions_taken":    r.get("actions", 0),
            "error_count":      r.get("errors", 0),
            "domain_filtered":  r.get("domain_filtered", 0),
            "no_address_count": r.get("no_address", 0),
            "lookup_disabled_count": r.get("lookup_disabled", 0),
            "no_token_count":   r.get("no_token", 0),
            "lookup_failed_count": r.get("lookup_failed", 0),
            "capped":           bool(r.get("capped", False)),
            "truncated":        bool(r.get("truncated", False)),
            "duration_sec":     float(r.get("duration", 0)),
            "event_type":       "import_run_summary",
        })
    return _upload(rule_id, IMPORT_AUDIT_STREAM, records, endpoint)
