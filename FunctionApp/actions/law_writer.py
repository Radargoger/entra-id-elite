"""
Log Analytics Workspace (LAW) writer via Azure Monitor Logs Ingestion API (DCR-based).
Replaces the legacy HTTP Data Collector API (deprecated 2026-09-14).

Migration notes:
- Old: HMAC-SHA256 signed POST to ods.opinsights.azure.com/api/logs
- New: OAuth Bearer token via UAMI/DefaultAzureCredential, POST to DCR endpoint
- Auth: Monitoring Metrics Publisher role on the DCR scope (assigned to UAMI)
- Schema: explicit per-table column declarations in DCR streamDeclarations

Password policy: if EnableLogPlaintextPassword=false (default), plaintext is stripped.
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

BATCH_SIZE = 1000  # Logs Ingestion API allows up to 1MB per call; 1000 records is safe default
MAX_FIELD_LEN = 30000

# Singleton client (re-used across function invocations)
_client: LogsIngestionClient | None = None
_client_endpoint: str = ""


def _get_client(endpoint: str) -> LogsIngestionClient | None:
    """Return cached LogsIngestionClient or build one with DefaultAzureCredential."""
    global _client, _client_endpoint
    if _client is None or _client_endpoint != endpoint:
        try:
            credential = DefaultAzureCredential()
            _client = LogsIngestionClient(endpoint=endpoint, credential=credential)
            _client_endpoint = endpoint
            logger.info("[LAW] LogsIngestionClient initialized for %s", endpoint)
        except Exception as e:
            logger.error("[LAW] Failed to initialize LogsIngestionClient: %s", e)
            return None
    return _client


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


def _clean_record(rec: dict, enable_log_plaintext: bool) -> dict:
    """Remove internal-only fields, enforce password policy, truncate long strings, add TimeGenerated."""
    out = {}
    skip_keys = {"_checkpoint_update", "sanitized", "entra_user_id", "_empty_marker"}
    for k, v in rec.items():
        if k in skip_keys:
            continue
        if k == "password" and not enable_log_plaintext:
            continue
        if isinstance(v, str) and len(v) > MAX_FIELD_LEN:
            v = v[:MAX_FIELD_LEN] + "...[truncated]"
        out[k] = v
    # TimeGenerated is required by DCR
    out.setdefault("TimeGenerated", datetime.now(timezone.utc).isoformat())
    return out


def write_records(conf: dict, source_name: str, records: list):
    """Write source records to appropriate LAW table in batches via DCR Logs Ingestion API."""
    stream_name = STREAM_MAP.get(source_name)
    if not stream_name:
        logger.warning("[LAW] Unknown source: %s — skipping", source_name)
        return

    rule_id = conf.get("dcr_immutable_id")
    endpoint = conf.get("dcr_endpoint")
    if not rule_id or not endpoint:
        logger.error("[LAW] DCR_IMMUTABLE_ID or DCR_ENDPOINT missing — cannot write %s records", source_name)
        return

    enable_log_plaintext = conf.get("enable_log_plaintext_password", False)
    cleaned = [_clean_record(r, enable_log_plaintext) for r in records]

    for i in range(0, len(cleaned), BATCH_SIZE):
        batch = cleaned[i:i + BATCH_SIZE]
        _upload(rule_id, stream_name, batch, endpoint)


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
    """Write audit summary records to SOCRadar_EntraID_Audit_CL table."""
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
            "total_records":    r.get("total", 0),
            "employee_records": r.get("employees", 0),
            "found_count":      r.get("found", 0),
            "not_found_count":  r.get("not_found", 0),
            "actions_taken":    r.get("actions", 0),
            "error_count":      r.get("errors", 0),
            "duration_sec":     float(r.get("duration", 0)),
        })
    return _upload(rule_id, AUDIT_STREAM, records, endpoint)
