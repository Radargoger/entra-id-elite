"""
SOCRadar Entra ID Integration — Azure Function App
Timer-triggered function that pulls leaked employee credentials from SOCRadar
and takes automated remediation actions in Microsoft Entra ID.

Sources:
  - Botnet Data v2
  - PII Exposure v2
  - VIP Protection v2
"""

import os
import time
import logging
import functools
import azure.functions as func
from azure.identity import DefaultAzureCredential

from utils import config as cfg
from utils import checkpoint as cp
from utils.logger import audit_summary

from sources import botnet as src_botnet
from sources import pii as src_pii
from sources import vip as src_vip

from actions import entra_id as entra
from actions import law_writer as law
from actions import sentinel as sent
from actions import socradar as socradar_api
from actions import action_ledger as ledger_mod

logger = logging.getLogger(__name__)
app = func.FunctionApp()

# Time budget per run. Function timeout is 10 min (Y1 Consumption hard cap).
# Leave ~2 min headroom for cleanup (LAW write + checkpoint save).
TIME_BUDGET_SECONDS = 8 * 60
# Share of a slot spent pulling records; the rest looks them up in Entra ID.
FETCH_BUDGET_SHARE = 0.4
# Measured against the live feed: ~0.35s per record for the Graph lookup plus
# per-record bookkeeping. Used to size a fetch to what the run can process.
SECONDS_PER_LOOKUP = 0.4
# Always pull at least this much, so a slow run still makes progress.
PAGE_MIN_RECORDS = 50
# After this many failed attempts at the same window, move past it: a stuck
# window is worse than a lost one, because nothing behind it is ever read.
MAX_CONSECUTIVE_HOLDS = 5

# Honour RUN_ON_STARTUP env var (ARM parameter). Default true.
_RUN_ON_STARTUP = os.environ.get("RUN_ON_STARTUP", "true").strip().lower() in ("true", "1", "yes")


def _required_graph_permissions(conf: dict) -> list[tuple[str, str]]:
    """Return the Graph application permissions implied by the current config."""
    permissions = []

    if conf["enable_user_lookup"]:
        permissions.append(("User.Read.All", "look up leaked identities in Entra ID"))
    if conf["enable_revoke_session"]:
        permissions.append(("User.RevokeSessions.All", "revoke active user sessions"))
    if conf["enable_add_to_group"] or conf["enable_remove_from_group"]:
        permissions.append(("GroupMember.ReadWrite.All", "add or remove users from a security group"))
    if conf["enable_password_change"]:
        permissions.append(("User-PasswordProfile.ReadWrite.All", "force password change at next sign-in"))
    if conf["enable_disable_account"] or conf["enable_enable_account"]:
        permissions.append(("User.EnableDisableAccount.All", "disable or re-enable user accounts"))
    if conf["enable_confirm_risky"]:
        permissions.append(("IdentityRiskyUser.ReadWrite.All", "confirm compromised users in Identity Protection"))
    if conf["enable_force_mfa_reregistration"]:
        permissions.append(("UserAuthenticationMethod.ReadWrite.All", "delete MFA methods to force re-registration"))

    return permissions


@app.timer_trigger(
    schedule="%POLLING_SCHEDULE%",
    arg_name="timer",
    run_on_startup=_RUN_ON_STARTUP
)
def socradar_entra_id_import(timer: func.TimerRequest) -> None:
    start_time = time.time()
    logger.info("=== SOCRadar Entra ID Integration started ===")

    if timer.past_due:
        logger.warning("Timer is past due, running anyway")

    conf = cfg.load()
    credential = DefaultAzureCredential()

    for permission, reason in _required_graph_permissions(conf):
        logger.info("[ENTRA] Config requires %s — %s", permission, reason)

    if conf["enable_confirm_risky"]:
        logger.info("[ENTRA] EnableConfirmRisky also requires an Entra ID P2 licence")

    if not conf["enable_user_lookup"]:
        logger.warning("[ENTRA] EnableUserLookup=false — User.Read.All is optional, but Entra lookup and all Entra-targeted actions will be skipped")
        if any((
            conf["enable_revoke_session"],
            conf["enable_add_to_group"],
            conf["enable_remove_from_group"],
            conf["enable_password_change"],
            conf["enable_disable_account"],
            conf["enable_enable_account"],
            conf["enable_confirm_risky"],
            conf["enable_force_mfa_reregistration"],
            conf["enable_ropc"],
        )):
            logger.warning("[ENTRA] One or more Entra action toggles are enabled, but they cannot run while EnableUserLookup=false")
    sources_to_run = []
    if conf["enable_botnet_source"]:
        sources_to_run.append("botnet")
    if conf["enable_pii_source"]:
        sources_to_run.append("pii")
    if conf["enable_vip_source"]:
        logger.info("[VIP] Source enabled")
        sources_to_run.append("vip")

    logger.info("Active sources: %s", sources_to_run)

    rows = _import_company_rows(conf)
    logger.info("[IMPORT] %d company row(s) in scope: %s",
                len(rows), ", ".join(r["company_id"] for r in rows))
    logger.info("[IMPORT] Directory action mode: %s (ceiling %d per run)",
                conf["entra_action_mode"], conf["entra_max_actions_per_run"])

    audit_results = []
    hard_deadline = start_time + TIME_BUDGET_SECONDS
    # Every (company, source) pair gets an equal slice. Without this the first
    # pair can consume the whole budget and the ones behind it never run — and
    # an empty audit row is indistinguishable from "nothing was leaked".
    slots = max(1, len(rows) * max(1, len(sources_to_run)))
    slot_budget = TIME_BUDGET_SECONDS / slots

    for row in rows:
        ccfg = _import_company_conf(conf, row)
        company_id = ccfg["socradar_company_id"]

        if not ccfg["socradar_api_key"]:
            logger.error("[IMPORT] company %s has no API key — skipped", company_id)
            for source_name in sources_to_run:
                audit_results.append(_empty_audit(source_name, company_id, errors=1))
            continue

        tenant_headers_map = _acquire_tenant_tokens(ccfg, company_id)

        for source_name in sources_to_run:
            if time.time() >= hard_deadline:
                logger.warning("[%s] company %s skipped — run budget exhausted",
                               source_name.upper(), company_id)
                audit_results.append(_empty_audit(source_name, company_id, errors=0,
                                                  truncated=True))
                continue

            src_start = time.time()
            try:
                result = _process_source(
                    source_name=source_name,
                    conf=ccfg,
                    credential=credential,
                    tenant_headers_map=tenant_headers_map,
                    deadline=min(src_start + slot_budget, hard_deadline),
                    checkpoint_key=_checkpoint_key(source_name, company_id, row),
                )
                result["company_id"] = company_id
                result["duration"] = round(time.time() - src_start, 1)
                audit_results.append(result)
            except Exception as e:
                logger.error("[%s] company %s unhandled error: %s",
                             source_name.upper(), company_id, e, exc_info=True)
                failed = _empty_audit(source_name, company_id, errors=1)
                failed["duration"] = round(time.time() - src_start, 1)
                audit_results.append(failed)

    # Write audit log
    for r in audit_results:
        audit_summary(
            source=r["source"], total=r["total"], employees=r["employees"],
            found=r["found"], not_found=r["not_found"], actions=r["actions"],
            errors=r["errors"], duration_sec=r.get("duration", 0),
            domain_filtered=r.get("domain_filtered", 0),
            no_address=r.get("no_address", 0),
            lookup_disabled=r.get("lookup_disabled", 0),
            no_token=r.get("no_token", 0),
            lookup_failed=r.get("lookup_failed", 0),
        )

    if conf.get("dcr_immutable_id") and conf.get("dcr_endpoint"):
        law.write_audit(conf, audit_results)

    total_duration = round(time.time() - start_time, 1)
    logger.info("=== SOCRadar Entra ID Integration finished in %.1fs ===", total_duration)


@app.route(route="leak/preview", auth_level=func.AuthLevel.FUNCTION, methods=["GET"])
def leak_preview(req: func.HttpRequest) -> func.HttpResponse:
    """Read-only view of what leak monitoring would do, per company.

    Shows which tenants each company is searched in and which responses are
    armed. Reads nothing from the feeds and never touches the directory, so it
    is safe to call at any time.

    GET /api/leak/preview?code=<function-key>
    """
    import json as _json
    try:
        conf = cfg.load()
        sources = [s for s, on in (("botnet", conf["enable_botnet_source"]),
                                   ("pii", conf["enable_pii_source"]),
                                   ("vip", conf["enable_vip_source"])) if on]
        companies = []
        for row in _import_company_rows(conf):
            ccfg = _import_company_conf(conf, row)
            company_id = ccfg["socradar_company_id"]
            # Which tenants can actually be reached right now. Listing the
            # configured tenants alone would report a healthy setup while every
            # lookup silently finds nothing for want of a token.
            reachable = (list(_acquire_tenant_tokens(ccfg, company_id))
                         if conf["enable_user_lookup"] else [])
            unreachable = [t for t in ccfg["tenant_ids"] if t not in reachable]
            companies.append({
                "company_id": company_id,
                "own_tenants": ccfg["tenant_ids"],
                "tenants_reachable": reachable,
                "tenants_unreachable": unreachable,
                "has_api_key": bool(ccfg["socradar_api_key"]),
                "ready": bool(ccfg["socradar_api_key"]) and not unreachable,
                "checkpoint_keys": {s: _checkpoint_key(s, company_id, row)
                                    for s in sources},
            })
        payload = {
            "enabled": bool(sources) and conf["enable_user_lookup"],
            "sources": sources,
            "action_mode": conf["entra_action_mode"],
            "max_actions_per_run": conf["entra_max_actions_per_run"],
            "armed_actions": [name for name, on in (
                ("revoke_session", conf["enable_revoke_session"]),
                ("force_password_change", conf["enable_password_change"]),
                ("disable_account", conf["enable_disable_account"]),
                ("enable_account", conf["enable_enable_account"]),
                ("force_mfa_reregistration", conf["enable_force_mfa_reregistration"]),
                ("confirm_risky", conf["enable_confirm_risky"]),
                ("add_to_group", conf["enable_add_to_group"] and bool(conf["security_group_id"])),
            ) if on],
            "companies": companies,
        }
        return func.HttpResponse(_json.dumps(payload, ensure_ascii=False),
                                 status_code=200, mimetype="application/json")
    except Exception as e:
        logger.error("[LEAK-PREVIEW] failed: %s", e)
        return func.HttpResponse('{"error": "preview failed, see logs"}',
                                 status_code=500, mimetype="application/json")


@app.route(route="leak/probe", auth_level=func.AuthLevel.FUNCTION, methods=["POST"])
def leak_probe(req: func.HttpRequest) -> func.HttpResponse:
    """Answer "what would happen to this address for this company?".

    Looks the address up in that company's OWN tenants only — the same lookup
    the timer performs — and reports where it was found and which responses
    would run.

    Responding requires three separate consents, and all three must hold:
      1. the deployment runs in apply mode,
      2. the caller asks for it explicitly with "apply": true,
      3. the address is present in this company's own tenants.
    Miss any one and the call stays read-only; `apply_reason` says which.

    POST /api/leak/probe?code=<function-key>
      {"email": "...", "company_id": "...", "apply": false}
    """
    import json as _json
    try:
        body = req.get_json()
    except ValueError:
        return func.HttpResponse('{"error": "body must be JSON"}',
                                 status_code=400, mimetype="application/json")

    email = (body.get("email") or "").strip().lower()
    company_id = str(body.get("company_id") or "").strip()
    if not email or "@" not in email:
        return func.HttpResponse('{"error": "email is required"}',
                                 status_code=400, mimetype="application/json")

    try:
        conf = cfg.load()
        rows = _import_company_rows(conf)
        row = next((r for r in rows if str(r["company_id"]) == company_id), None)
        if row is None:
            known = ", ".join(str(r["company_id"]) for r in rows)
            return func.HttpResponse(
                _json.dumps({"error": f"unknown company_id; configured: {known}"}),
                status_code=404, mimetype="application/json")

        ccfg = _import_company_conf(conf, row)
        headers_map = _acquire_tenant_tokens(ccfg, company_id)

        searched, found_tenant, user_id, enabled = [], None, "", None
        for tenant_id, headers in headers_map.items():
            searched.append(tenant_id)
            user, status = entra.lookup_user(email, headers)
            if user is not None:
                found_tenant = tenant_id
                user_id = user.get("id", "")
                enabled = user.get("accountEnabled")
                break

        # Reversible responses only. Disabling an account, resetting MFA or
        # flagging someone in Identity Protection stays with the timer, where
        # the run-wide ceiling applies.
        would_run = [name for name, on in (
            ("revoke_session", conf["enable_revoke_session"]),
            ("force_password_change", conf["enable_password_change"]),
        ) if on] if found_tenant else []

        # The same allowlist the timer applies. Without it an operator holding
        # the function key could act on any address that happens to exist in the
        # tenant, including one this deployment was never meant to touch.
        allow_domains = ccfg.get("verified_domains", [])
        _, _, email_domain = email.partition("@")
        domain_ok = not allow_domains or email_domain.lower() in allow_domains

        wants_apply = bool(body.get("apply"))
        if not searched:
            # No tenant was reached, so nothing was established about this
            # address. Reporting "not found" here would answer a question the
            # run never asked — the same conflation of an empty result with an
            # unread one that this codebase has been bitten by before. Say which
            # one it is, because the operator's next step differs: a real miss
            # means the address is not in the directory, an unread one means the
            # lookup is switched off or the tenant could not be reached.
            apply_reason = ("no tenant was searched: user lookup is disabled"
                            if not conf.get("enable_user_lookup", True)
                            else "no tenant was searched: no Graph token for this company")
        elif not found_tenant:
            apply_reason = "not found in this company's own tenants"
        elif conf["entra_action_mode"] != "apply":
            apply_reason = "deployment is in plan mode"
        elif not wants_apply:
            apply_reason = "request did not ask to apply"
        elif not domain_ok:
            apply_reason = "address is outside the verified-domain allowlist"
        else:
            apply_reason = "applied"

        applied = []
        if apply_reason == "applied":
            headers = headers_map[found_tenant]
            # Same ledger the timer writes to, keyed on today's date: repeating
            # the call does not repeat the action, so a loop over this endpoint
            # cannot turn into a stream of directory changes.
            from datetime import datetime as _dt, timezone as _tz
            window_date = _dt.now(_tz.utc).strftime("%Y-%m-%d")
            ledger = ledger_mod.ActionLedger(
                conf["storage_account_name"], DefaultAzureCredential(),
                "probe", company_id)
            for name in would_run:
                if ledger.already_applied(email, "probe", name, window_date):
                    applied.append(f"{name}_skipped_idempotent")
                    continue
                if name == "revoke_session":
                    ok = entra.revoke_sessions(user_id, headers)
                else:
                    ok = entra.force_password_change(user_id, headers)
                applied.append(name if ok else f"{name}_failed")
                if ok:
                    _record_applied_safely(ledger, email, "probe", name,
                                           window_date, applied)
            logger.warning("[LEAK-PROBE] applied %s to %s in tenant %s (company %s)",
                           applied, email, found_tenant, company_id)
            # The probe writes to its own partition, which no timer run cleans.
            # Small slice: this is a synchronous request and the caller waits.
            try:
                ledger.purge_before(
                    ledger_mod.cutoff_date(
                        conf.get("leak_ledger_retention_days", 90),
                        active_window=window_date),
                    max_rows=50)
            except Exception as e:
                logger.warning("[LEAK-PROBE] ledger cleanup failed (%s) — rows kept", e)
            # A directory change made outside the timer still belongs in the
            # audit trail, or the only record of it is a log line.
            if any(a in would_run for a in applied):
                law.write_lifecycle_event(
                    conf, event_type="leak_probe_applied",
                    tenant_id=found_tenant,
                    details=f"company={company_id} actions={','.join(applied)}")

        payload = {
            "email": email,
            "company_id": company_id,
            "own_tenants": ccfg["tenant_ids"],
            "tenants_searched": searched,
            "found": found_tenant is not None,
            "found_in_tenant": found_tenant or "",
            "account_enabled": enabled,
            "user_id_prefix": user_id[:8],
            "action_mode": conf["entra_action_mode"],
            "would_run": would_run,
            "applied": applied,
            "apply_reason": apply_reason,
            "mutated": bool(applied),
        }
        logger.info("[LEAK-PROBE] company=%s email=%s searched=%s found_in=%s applied=%s",
                    company_id, email, searched, found_tenant or "-", applied)
        return func.HttpResponse(_json.dumps(payload, ensure_ascii=False),
                                 status_code=200, mimetype="application/json")
    except Exception as e:
        logger.error("[LEAK-PROBE] failed: %s", e)
        return func.HttpResponse('{"error": "probe failed, see logs"}',
                                 status_code=500, mimetype="application/json")


def _import_company_rows(conf: dict) -> list:
    """Companies this import runs for.

    With FORMER_COMPANY_MAP set each row is its own company; without it the
    legacy single-company app settings apply.
    """
    raw = (conf.get("company_map_raw") or "").strip()
    if not raw:
        return [{
            "company_id": conf["socradar_company_id"],
            "api_key": conf["socradar_api_key"],
            "own_tenants": cfg.resolve_tenants(conf),
            "_legacy": True,
        }]

    rows, errors = companies_api.parse_company_map(raw, os.environ)
    for err in errors:
        logger.error("[IMPORT] company map: %s", err)
    if errors:
        # A dropped row is a company that will not be looked at this run, and a
        # log line is not somewhere anyone looks. With the other rows parsing
        # fine the run reports a clean sweep, and the company that fell out of
        # the configuration is missing from the audit trail rather than marked
        # absent in it.
        try:
            law.write_lifecycle_event(
                conf, event_type="company_row_dropped",
                details=(f"{len(errors)} of {len(rows) + len(errors)} configured "
                         f"row(s) unusable and not processed: "
                         f"{'; '.join(errors)}")[:900])
        except Exception as e:
            logger.error("[IMPORT] company map errors could not be recorded: %s", e)
    if not rows:
        # A broken map must not collapse into one placeholder company: that
        # reports success for companies nobody actually looked at.
        raise RuntimeError("FORMER_COMPANY_MAP produced no usable rows")
    return rows


def _import_company_conf(conf: dict, row: dict) -> dict:
    """Per-company view of the config.

    The tenant list is the row's OWN tenants: a company's leaked credentials are
    only ever searched — and acted on — in that company's own directory. The
    global ENTRA_TENANT_IDS is deliberately not consulted here, otherwise one
    company's leak could trigger a mutation in another company's tenant.
    """
    out = dict(conf)
    out["socradar_company_id"] = row["company_id"]
    out["socradar_api_key"] = row.get("api_key") or ""
    out["tenant_ids"] = list(row.get("own_tenants") or [])
    out["tenant_id"] = ""
    return out


def _checkpoint_key(source_name: str, company_id: str, row: dict) -> str:
    """Checkpoint partition. Companies must not share one, or the second company
    resumes from the first one's position and skips its own backlog."""
    if row.get("_legacy"):
        return source_name  # keep existing deployments' position in the feed
    return f"{source_name}:{company_id}"


def _empty_audit(source_name: str, company_id: str, errors: int,
                 truncated: bool = False) -> dict:
    return {
        "source": source_name, "company_id": company_id,
        "total": 0, "employees": 0, "found": 0, "not_found": 0,
        "actions": 0, "errors": errors, "duration": 0.0,
        "domain_filtered": 0, "no_address": 0, "lookup_disabled": 0, "no_token": 0,
        "lookup_failed": 0,
        "capped": False, "truncated": truncated,
    }


def _acquire_tenant_tokens(conf: dict, company_id: str) -> dict:
    """Graph tokens for this company's own tenants, in order."""
    headers = {}
    if not conf["enable_user_lookup"]:
        return headers

    tenants = cfg.resolve_tenants(conf)
    logger.info("[ENTRA] company %s: lookup across %d tenant(s): %s",
                company_id, len(tenants), ", ".join(tenants))

    for tenant_id in tenants:
        try:
            graph_token = entra.get_graph_token(
                tenant_id=tenant_id,
                client_id=conf["client_id"]
            )
            headers[tenant_id] = {
                "Authorization": f"Bearer {graph_token}",
                "Content-Type": "application/json"
            }
        except entra.ConsentRevokedError as e:
            logger.error(
                "[ENTRA] Consent issue for tenant %s (%s): %s — this tenant will be skipped",
                e.tenant_id, e.aadsts_code, e
            )
            law.write_lifecycle_event(
                conf, event_type="consent_revoked", tenant_id=e.tenant_id,
                details=str(e), extra={"aadsts_code": e.aadsts_code}
            )
        except Exception as e:
            logger.error("[ENTRA] Failed to acquire Graph token for tenant %s — this tenant will be skipped: %s",
                         tenant_id, e)
            law.write_lifecycle_event(
                conf, event_type="token_acquisition_failed",
                tenant_id=tenant_id, details=str(e)[:500]
            )

    if tenants and not headers:
        logger.error("[ENTRA] company %s: no tenant produced a usable token — Entra actions skipped",
                     company_id)
    return headers


def _record_applied_safely(ledger, email: str, source_name: str,
                           action_name: str, window_date: str, taken: list) -> bool:
    """A mutation that happened but could not be recorded must not become a
    mutation that happens twice. Before this, a ledger write that raised after
    a successful Graph action was counted as a processing failure, which held
    the window — and the re-read then repeated the action, because the ledger
    had no memory of it. For an MFA reset that is real harm. So the failure is
    retried once, then absorbed: the action is tagged `_unrecorded`, the error
    is logged, and the window is allowed to move on. Skipping a possible retry
    is the cheaper mistake; repeating an irreversible action is not.
    """
    for attempt in (1, 2):
        try:
            ledger.record_applied(email, source_name, action_name, window_date)
            return True
        except Exception as e:
            if attempt == 1:
                continue
            logger.error(
                "[LEDGER] %s applied to %s but could NOT be recorded (%s). "
                "Tagged _unrecorded; if this window is re-read for another "
                "reason, the action may repeat.", action_name, email, e)
    taken.append(f"{action_name}_unrecorded")
    return False


def _process_source(source_name: str, conf: dict, credential, tenant_headers_map: dict,
                    deadline: float, checkpoint_key: str = "") -> dict:
    """Fetch one source for one company, process each record, return audit dict.

    `tenant_headers_map` holds only this company's own tenants, so a match can
    never occur in another company's directory. For each employee lookup_user is
    tried against those tenants in order; first match wins and all subsequent
    actions run against that tenant's headers.

    `deadline` is the wall-clock instant this (company, source) slot must stop at.
    `checkpoint_key` is the storage partition; companies do not share one.
    """
    partition = checkpoint_key or source_name
    chk = cp.load(conf["storage_account_name"], credential, partition)

    # Only pull what this run can also process. Fetching a whole backlog and
    # looking up a tenth of it holds the checkpoint back, so the next run reads
    # the same pages again and the feed never advances.
    remaining = min(TIME_BUDGET_SECONDS, max(0.0, deadline - time.time()))
    fetch_deadline = time.time() + max(10.0, remaining * FETCH_BUDGET_SHARE)
    max_records = None
    if conf["enable_user_lookup"]:
        lookup_seconds = remaining * (1 - FETCH_BUDGET_SHARE)
        max_records = max(PAGE_MIN_RECORDS, int(lookup_seconds / SECONDS_PER_LOOKUP))

    # Fetch employees from source
    if source_name == "botnet":
        employees = src_botnet.fetch(conf, chk, fetch_deadline, max_records)
    elif source_name == "pii":
        employees = src_pii.fetch(conf, chk, fetch_deadline, max_records)
    elif source_name == "vip":
        employees = src_vip.fetch(conf, chk, fetch_deadline, max_records)
    else:
        # Duration is set by the caller.
        return {"source": source_name, "total": 0, "employees": 0,
                "found": 0, "not_found": 0, "actions": 0, "errors": 0,
                "no_address": 0}

    found = not_found = actions = errors = domain_filtered = 0
    no_address = 0
    # Two ways a record can leave without ever being looked up. They are counted
    # apart because they mean opposite things: the operator turned lookup off, or
    # we could not reach the directory at all. Only the second one is a failure.
    lookup_disabled = no_token = 0
    lookup_failures = 0
    # A record that raised on the way through never reaches Log Analytics.
    # Counted separately from `errors` because only this class of failure means
    # "this window still has unread work in it".
    processing_failures = 0
    records = []
    # Per-tenant 403 counter: if a tenant returns 403 three times in a row,
    # drop it from the lookup map (admin consent missing — no point retrying).
    # Healthy tenants in the same map continue to function.
    tenant_403_counts = {tid: 0 for tid in tenant_headers_map}

    # Extract checkpoint before the loop — it sits on the last record and
    # will be popped from emp before appending to LAW records below.
    new_checkpoint = employees[-1].get("_checkpoint_update", {}) if employees else {}
    # The checkpoint describes the whole fetch, so it may only be saved when
    # every record was processed. Saving it after an early exit would advance
    # past records nobody looked at, and they are never fetched again.
    truncated = False

    # Directory mutations are gated twice, independently of the per-action
    # toggles: the run-wide ceiling below, and the action mode (plan | apply).
    apply_mode = conf.get("entra_action_mode", "plan") == "apply"
    max_actions = conf.get("entra_max_actions_per_run", 50)
    capped = False

    # Idempotency ledger (code-review B1): prevent duplicate actions when the
    # same window is re-read. Plan-only mode uses an in-memory ledger that
    # never persists, so it cannot block future apply runs.
    window_date = cp.get_start_date(chk, conf.get("initial_lookback_minutes", 43200),
                                    conf.get("initial_start_date", ""))
    if apply_mode:
        try:
            ledger = ledger_mod.ActionLedger(
                conf["storage_account_name"], credential,
                source_name, conf.get("socradar_company_id", ""))
        except Exception as e:
            # Without the ledger there is no way to tell a repeat from a
            # first-time action, so applying could act twice on the same
            # person. Stop this source rather than quietly dropping the
            # guarantee by falling back to an in-memory one.
            raise RuntimeError(
                f"apply mode requires the action ledger and it is unavailable: {e}") from e
    else:
        ledger = ledger_mod.InMemoryActionLedger()

    for emp in employees:
        # The marker is the fetcher's way of saying "nothing usable came back".
        # It is bookkeeping, not a finding: letting it walk the loop below filed
        # it under skipped_no_address, so an empty run reported total=0 with one
        # address-less record in it.
        if emp.get("_empty_marker"):
            continue

        # Per-employee slot check — graceful exit so LAW write + checkpoint
        # save finish within the function timeout.
        if time.time() >= deadline:
            logger.warning(
                "[%s] Time slot exhausted mid-source. Stopping early — %d records processed so far. Checkpoint held back; the next run re-fetches this window.",
                source_name.upper(), len(records)
            )
            truncated = True
            break

        try:
            email = emp.get("email") or emp.get("user", "")

            # The plaintext password is needed only by the optional ROPC check
            # further down. Lift it into a local now and drop it from the record
            # immediately, so none of the early-exit paths below can carry it
            # onward into logs or Log Analytics. This has to happen before the
            # first early exit, not after the second: an address-less record
            # leaves by the branch just below, and it carries a credential too.
            raw_pw = None
            if emp.get("sanitized"):
                raw_pw = emp["sanitized"].pop("_raw", None)

            if not email:
                # Not every feed record carries an address. VIP is the standing
                # case: those records name a person, and an address, where there
                # is one at all, sits in free text. Dropping the record here made
                # it vanish from Log Analytics with no counter and no log line,
                # so the finding existed on the platform and nowhere in the
                # customer's own audit trail. Record it and say why.
                no_address += 1
                emp["entra_status"] = "skipped_no_address"
                emp["entra_tenant_id"] = ""
                emp["actions_taken"] = []
                emp.pop("_checkpoint_update", None)
                records.append(emp)
                continue

            # User lookup in Entra ID (skipped if Graph token unavailable or permissions missing)
            if not conf["enable_user_lookup"]:
                # The operator asked for findings without directory matching.
                # Nothing was missed, so the window may move on — but the record
                # still needs a bucket, or the audit row's parts stop adding up
                # to its total.
                lookup_disabled += 1
                emp["entra_status"] = "skipped_user_lookup_disabled"
                emp["entra_tenant_id"] = ""
                emp["actions_taken"] = []
                emp.pop("_checkpoint_update", None)
                records.append(emp)
                continue

            if not tenant_headers_map:
                # No tenant produced a usable token, so nobody in this window was
                # checked against the directory. Advancing past it would retire
                # those findings unread and they are never fetched again — the
                # exact loss the checkpoint rules exist to prevent. Count it and
                # hold; MAX_CONSECUTIVE_HOLDS still frees a permanently broken
                # tenant after a few attempts.
                no_token += 1
                emp["entra_status"] = "skipped_no_token"
                emp["entra_tenant_id"] = ""
                emp["actions_taken"] = []
                emp.pop("_checkpoint_update", None)
                records.append(emp)
                continue

            # Verified-domain allowlist gate. Applied before the per-tenant lookup
            # loop so we save Graph quota on every non-matching tenant, not just
            # the first. Empty allowlist disables filtering (backward compat).
            allow_domains = conf.get("verified_domains", [])
            if allow_domains:
                _, _, email_domain = email.partition("@")
                if not email_domain or email_domain.lower() not in allow_domains:
                    domain_filtered += 1
                    emp["entra_status"] = "skipped_domain_allowlist"
                    emp["entra_tenant_id"] = ""
                    emp["actions_taken"] = []
                    emp.pop("_checkpoint_update", None)
                    records.append(emp)
                    continue

            # Multi-tenant lookup: try each tenant in order, first match wins.
            # Track per-lookup whether any tenant returned 403 — distinguishes
            # genuine "not found" from "permission denied silently turned into 404".
            user_info = None
            lookup_status = None
            found_tenant = None
            seen_403_this_lookup = False
            seen_error_this_lookup = False
            for tenant_id in list(tenant_headers_map.keys()):
                headers = tenant_headers_map[tenant_id]
                u, status = entra.lookup_user(email, headers)
                if u is not None:
                    user_info = u
                    lookup_status = status
                    found_tenant = tenant_id
                    tenant_403_counts[tenant_id] = 0  # reset on any success
                    break
                if status == 403:
                    seen_403_this_lookup = True
                    tenant_403_counts[tenant_id] = tenant_403_counts.get(tenant_id, 0) + 1
                    if tenant_403_counts[tenant_id] >= 3:
                        logger.warning(
                            "[%s] Tenant %s returned 3 consecutive 403s — dropping from lookup map (admin consent likely missing)",
                            source_name.upper(), tenant_id
                        )
                        tenant_headers_map.pop(tenant_id, None)
                elif status != 404:
                    # Network error, 5xx, exhausted throttling: we did not learn
                    # whether this person is in the tenant. Calling that
                    # "not found" would leave a real compromised account alone.
                    seen_error_this_lookup = True
                    tenant_403_counts[tenant_id] = 0
                else:
                    tenant_403_counts[tenant_id] = 0
                lookup_status = status  # last seen status

            # Fully exhausted lookup map (all tenants 403'd out mid-loop)
            if not tenant_headers_map and user_info is None:
                errors += 1
                logger.warning(
                    "[%s] %s → all tenants exhausted permission errors (403). Marking as lookup_permission_denied. Admin consent likely missing.",
                    source_name.upper(), email
                )
                lookup_failures += 1
                emp["entra_status"] = "lookup_permission_denied"
                emp["entra_tenant_id"] = ""
                emp["actions_taken"] = []
                emp.pop("_checkpoint_update", None)
                records.append(emp)
                continue

            if user_info is None:
                if seen_403_this_lookup:
                    # User wasn't found in any tenant but at least one tenant returned 403.
                    # Treat as permission denied, not "not_found" — prevents silent false negatives
                    # when admin consent has not yet been granted on Path 1.
                    errors += 1
                    lookup_failures += 1
                    logger.warning(
                        "[%s] %s → lookup returned 403 (no 200/404 from any tenant). entra_status=lookup_permission_denied",
                        source_name.upper(), email
                    )
                    emp["entra_status"] = "lookup_permission_denied"
                elif seen_error_this_lookup:
                    # The lookup failed rather than came back empty. Record it as
                    # an error and hold the checkpoint, so this window is read
                    # again instead of being written off as "nobody was affected".
                    errors += 1
                    lookup_failures += 1
                    logger.warning("[%s] %s → lookup failed (HTTP %s); will be retried",
                                   source_name.upper(), email, lookup_status)
                    emp["entra_status"] = "lookup_failed"
                else:
                    not_found += 1
                    emp["entra_status"] = "not_found"
                emp["entra_tenant_id"] = ""
                emp["actions_taken"] = []
                emp.pop("_checkpoint_update", None)
                records.append(emp)
                continue

            found += 1
            emp["entra_status"] = "found"
            emp["entra_tenant_id"] = found_tenant
            # No default. Defaulting an absent property to True wrote "the
            # account was live" into the audit trail without ever having read
            # it — and Graph omits accountEnabled unless the lookup selects it,
            # so the default was the value every single found user got. An
            # unread field stays empty; the row then says "unknown", which is
            # true, instead of "enabled", which was a guess.
            if "accountEnabled" in user_info:
                emp["entra_account_enabled"] = user_info["accountEnabled"]
            emp["entra_user_id"] = user_info.get("id", "")

            # All subsequent actions use the headers of the tenant where the user was found.
            graph_headers = tenant_headers_map[found_tenant]

            # ROPC validation (only if plaintext password available)
            ropc_result = None
            if conf["enable_ropc"] and emp.get("sanitized", {}).get("is_plaintext") and raw_pw:
                ropc_result = entra.validate_password_ropc(
                    email=email,
                    password=raw_pw,
                    tenant_id=found_tenant,
                    client_id=conf["client_id"]
                )
            raw_pw = None  # remove from local scope immediately

            if ropc_result == "valid":
                emp["entra_status"] = "compromised"
                emp["severity"] = "CRITICAL"
            elif ropc_result in ("invalid", "mfa_blocked"):
                emp["severity"] = "MEDIUM"
            else:
                emp["severity"] = "MEDIUM"  # default

            # Take actions. Every directory mutation goes through the same two
            # gates, so a feed that suddenly returns thousands of records cannot
            # turn into thousands of account changes, and plan mode can be
            # trusted to touch nothing.
            taken = []
            user_id = emp["entra_user_id"]

            planned = []
            if conf["enable_revoke_session"]:
                planned.append(("revoke_session",
                                functools.partial(entra.revoke_sessions, user_id, graph_headers)))
            if conf["enable_add_to_group"] and conf["security_group_id"]:
                planned.append(("add_to_group",
                                functools.partial(entra.add_to_group, user_id, conf["security_group_id"], graph_headers)))
            if conf["enable_remove_from_group"] and conf["security_group_id"]:
                planned.append(("remove_from_group",
                                functools.partial(entra.remove_from_group, user_id, conf["security_group_id"], graph_headers)))
            if conf["enable_disable_account"]:
                planned.append(("disable_account",
                                functools.partial(entra.disable_account, user_id, graph_headers)))
            if conf["enable_enable_account"]:
                planned.append(("enable_account",
                                functools.partial(entra.enable_account, user_id, graph_headers)))
            if conf["enable_password_change"]:
                planned.append(("force_password_change",
                                functools.partial(entra.force_password_change, user_id, graph_headers)))
            if conf["enable_confirm_risky"]:
                planned.append(("confirm_risky",
                                functools.partial(entra.confirm_compromised, user_id, graph_headers)))

            # Order matters: already-done work is not work. Consulting the
            # ledger before the ceiling keeps a re-read window from spending the
            # whole budget on no-ops while genuinely new people never get a turn.
            for action_name, run_action in planned:
                if apply_mode and ledger.already_applied(email, source_name, action_name, window_date):
                    taken.append(f"{action_name}_skipped_idempotent")
                    continue
                if actions >= max_actions:
                    capped = True
                    taken.append(f"{action_name}_skipped_cap")
                    continue
                actions += 1
                if not apply_mode:
                    taken.append(f"{action_name}_planned")
                    continue
                ok = run_action()
                taken.append(action_name if ok else f"{action_name}_failed")
                if ok:
                    _record_applied_safely(ledger, email, source_name,
                                           action_name, window_date, taken)

            if conf["enable_force_mfa_reregistration"]:
                if apply_mode and ledger.already_applied(email, source_name, "force_mfa_rereg", window_date):
                    taken.append("force_mfa_rereg_skipped_idempotent")
                elif actions >= max_actions:
                    capped = True
                    taken.append("force_mfa_rereg_skipped_cap")
                elif not apply_mode:
                    actions += 1
                    taken.append("force_mfa_rereg_planned")
                else:
                    actions += 1
                    mfa_result = entra.force_mfa_reregistration(user_id, graph_headers)
                    if mfa_result["permission_denied"]:
                        logger.warning(
                            "[%s] force_mfa_rereg skipped — UserAuthenticationMethod.ReadWrite.All not granted",
                            source_name.upper()
                        )
                        taken.append("force_mfa_rereg_no_permission")
                    elif mfa_result["methods_deleted"] > 0:
                        taken.append("force_mfa_rereg")
                        _record_applied_safely(ledger, email, source_name,
                                               "force_mfa_rereg", window_date, taken)
                    elif mfa_result.get("errors"):
                        taken.append("force_mfa_rereg_failed")
                    else:
                        # No MFA methods to delete (user only has password method)
                        taken.append("force_mfa_rereg_no_methods")
                    emp["mfa_methods_deleted"] = mfa_result["methods_deleted"]
                    emp["mfa_methods_skipped"] = mfa_result["methods_skipped"]

            # An incident is a lasting side effect like any other action, so a
            # re-read window must not raise the same one twice.
            if apply_mode and conf["enable_create_incident"]:
                if ledger.already_applied(email, source_name, "create_incident", window_date):
                    taken.append("create_incident_skipped_idempotent")
                else:
                    ok = sent.create_incident(conf, email, source_name,
                                              emp.get("severity", "MEDIUM"), credential=credential)
                    taken.append("create_incident" if ok else "create_incident_failed")
                    if ok:
                        _record_applied_safely(ledger, email, source_name,
                                               "create_incident", window_date, taken)

            # Resolve SOCRadar alarm if user found in Entra ID
            alarm_id = emp.get("alarm_id")
            if apply_mode and conf.get("enable_resolve_alarm") and alarm_id:
                if ledger.already_applied(email, source_name, "resolve_alarm", window_date):
                    taken.append("resolve_alarm_skipped_idempotent")
                elif actions >= max_actions:
                    capped = True
                    taken.append("resolve_alarm_skipped_cap")
                else:
                    actions += 1
                    ok = socradar_api.resolve_alarm(
                        api_key=conf["socradar_api_key"],
                        company_id=conf["socradar_company_id"],
                        alarm_id=alarm_id,
                        comment=f"User {email} found in Entra ID — auto-resolved by SOCRadar Entra ID Integration",
                        base_url=conf.get("socradar_base_url", "https://platform.socradar.com")
                    )
                    taken.append("resolve_alarm" if ok else "resolve_alarm_failed")
                    if ok:
                        _record_applied_safely(ledger, email, source_name,
                                               "resolve_alarm", window_date, taken)

            emp["actions_taken"] = taken
            emp.pop("_checkpoint_update", None)  # internal key — must not reach LAW
            records.append(emp)

        except Exception as e:
            # This record never made it into `records`, so it will never reach
            # Log Analytics. Count it apart from `errors` so the checkpoint
            # knows the window still has unread work in it.
            logger.error("[%s] Error processing %s: %s", source_name.upper(), emp.get("email", "?"), e)
            errors += 1
            processing_failures += 1

    # Write source records to LAW (skip empty marker records)
    real_records = [r for r in records if not r.get("_empty_marker")]
    law_ok = True
    if real_records:
        law_ok = law.write_records(conf, source_name, real_records)

    # The checkpoint may only advance when this window is genuinely done with:
    # every record processed, every lookup answered, and the findings stored.
    # Advancing past records that were never looked up — or never written —
    # loses them for good, because the window is never read again.
    if not law_ok:
        errors += 1
        logger.error("[%s] LAW write failed — holding the checkpoint so this window is retried",
                     source_name.upper())
    if lookup_failures:
        logger.warning("[%s] %d lookup(s) failed — holding the checkpoint",
                       source_name.upper(), lookup_failures)
    if processing_failures:
        logger.error("[%s] %d record(s) raised before reaching Log Analytics — holding the checkpoint",
                     source_name.upper(), processing_failures)
    if no_token:
        logger.error("[%s] %d record(s) went unchecked — no tenant produced a Graph token. Holding the checkpoint.",
                     source_name.upper(), no_token)
    # A fetch that broke mid-stream leaves unread pages behind it. The fetcher
    # says so on the marker; without reading it here the run advanced its window
    # on the strength of pages it never received.
    fetch_failed = any(e.get("_fetch_failed") for e in employees)
    if fetch_failed:
        logger.error("[%s] the feed request failed — holding the checkpoint so the window is read again",
                     source_name.upper())
    # A capped APPLY run deliberately left actions untaken. Advancing the
    # window retired them for good — the README promised they were "left for
    # the next run", and until this line nothing made that true. On the re-read
    # the ledger skips everyone already acted on, so only the remainder spends
    # budget. Two deliberate exclusions:
    #   - plan mode: nothing is recorded there, so a re-read replans the same
    #     people at the same point forever — a hold cannot make progress, it
    #     can only burn five runs and end in a false "abandoned" event.
    #   - max_actions == 0: the gate is closed (typo-closed cap included);
    #     re-reading with a zero budget is the same livelock.
    # MAX_CONSECUTIVE_HOLDS below still bounds a feed that outruns the ceiling
    # every single run.
    capped_hold = capped and apply_mode and max_actions > 0
    if capped_hold:
        logger.warning("[%s] action ceiling reached — holding the checkpoint so "
                       "the remaining actions get their turn", source_name.upper())
    hold_checkpoint = (truncated or not law_ok or lookup_failures > 0
                       or processing_failures > 0 or no_token > 0 or fetch_failed
                       or capped_hold)

    # Holding forever is its own failure: a tenant that keeps erroring would
    # freeze the feed and re-report the same findings every run. After a few
    # attempts, move on and say so plainly rather than stalling in silence.
    holds = int(chk.get("consecutive_holds") or 0)
    if hold_checkpoint:
        holds += 1
        if holds >= MAX_CONSECUTIVE_HOLDS:
            logger.error(
                "[%s] window held %d times running — advancing past it. "
                "Records that could not be looked up will not be retried.",
                source_name.upper(), holds)
            law.write_lifecycle_event(
                conf, event_type="import_window_abandoned",
                details=f"{source_name}: advanced after {holds} failed attempts")
            hold_checkpoint = False
            holds = 0
    else:
        holds = 0

    if new_checkpoint and not hold_checkpoint:
        # The window is done, so its pinned identity is released with it.
        cp.save(conf["storage_account_name"], credential, partition,
                dict(new_checkpoint, consecutive_holds=0, active_window_start=""))
    elif hold_checkpoint:
        # Keep the position, but remember how many times we have held it.
        #
        # `chk` is empty on the very first run of a source. Requiring it here
        # meant a first run that held saved nothing at all, so consecutive_holds
        # never persisted and MAX_CONSECUTIVE_HOLDS could never trip: the same
        # window was re-read and its rows re-written on every run, forever, with
        # a log line each time that read like the safety feature working.
        # The window's own start is pinned alongside the counter. Recomputing it
        # from the lookback on the next run moved it a day, and the idempotency
        # key derived from it moved too, so the ledger stopped recognising a
        # repeat and the same person could be acted on a second time.
        cp.save(conf["storage_account_name"], credential, partition,
                dict(chk or {}, consecutive_holds=holds,
                     active_window_start=window_date))

    # The ledger only has to remember windows a re-read can still reach. Older
    # rows are dead weight that otherwise grows for the life of the
    # deployment, so each apply run drains a bounded slice of them.
    if apply_mode:
        try:
            dropped = ledger.purge_before(
                ledger_mod.cutoff_date(
                    conf.get("leak_ledger_retention_days", 90),
                    active_window=window_date))
            if dropped:
                logger.info("[%s] ledger: %d rows past retention removed",
                            source_name.upper(), dropped)
        except Exception as e:
            # Keeping stale rows is safe, so this must not fail the run. Being
            # quiet about it would not be safe, so it is reported.
            logger.warning("[%s] ledger cleanup failed (%s) — rows kept, "
                           "idempotency unaffected", source_name.upper(), e)

    # A marker is the source's way of saying "the fetch produced nothing usable",
    # which includes an API error. Counting it as a record reports total=1,
    # errors=0 for a run that never reached the feed.
    real_employees = [e for e in employees if not e.get("_empty_marker")]
    if fetch_failed:
        errors += 1
    if capped:
        logger.warning("[%s] company %s: action ceiling (%d) reached — remaining actions skipped",
                       source_name.upper(), conf.get("socradar_company_id", "?"), max_actions)

    # Duration is set by the caller (socradar_entra_id_import) after this returns,
    # so it always reflects real wall-clock time. Not included here to avoid a
    # silent-zero trap if a future caller forgets to overwrite it.
    return {
        "source":     source_name,
        "total":      len(real_employees),
        "employees":  len([e for e in real_employees if e.get("is_employee", True)]),
        "found":      found,
        "not_found":  not_found,
        "actions":    actions,
        "errors":     errors,
        "domain_filtered": domain_filtered,
        # Without these the arithmetic does not close: a record that carried no
        # address, or that nobody looked up, is neither found nor missed, so
        # total would exceed the parts and the difference would have no name.
        "no_address": no_address,
        "lookup_disabled": lookup_disabled,
        "no_token": no_token,
        # A lookup that failed is not a lookup that came back empty. Counting
        # these only in `errors` left them out of the buckets, so the totals
        # stopped adding up exactly when something had gone wrong — the case
        # the equation exists to surface.
        "lookup_failed": lookup_failures,
        "capped":     capped,
        # Without this a run that stopped at 12% is indistinguishable from a
        # complete one: "no findings" and "we never got that far" look alike.
        "truncated":  truncated,
    }


# ============================================================================
# ELITE: Former Employee sync (V1 cross-tenant suppression + V2 own leavers)
# ============================================================================
#
# Single reconcile per company (never two writers on the same list):
#
#   desired = (active Members of GROUP tenants)          <- V1, only if configured
#           | (disabled+deleted Members of OWN tenants)  <- V2, rule set v1
#           - (active Members of OWN tenants)            <- safety invariant
#
# Then diff against the SOCRadar former list (mock or real) and add/remove.
# All matching is email-based (objectId is tenant-scoped).

from sources import entra_users as src_users
from actions import socradar_former as former_api
from actions import former_manual as manual_api
from actions import former_planner as planner_api
from actions import former_ownership as ownership_api
from actions import former_guard as guard_api
from actions import former_audit as audit_api
from actions import former_companies as companies_api
from actions import former_lock as lock_api

_FORMER_RUN_ON_STARTUP = os.environ.get(
    "FORMER_RUN_ON_STARTUP", os.environ.get("RUN_ON_STARTUP", "true")
).strip().lower() in ("true", "1", "yes")

_GUARD_SOURCE = "former_guard"


def _prefetch_tenant_data(fconf: dict, tenant_ids: list, own_union: set) -> dict:
    """Read each tenant ONCE and share across companies (Topology 2: N
    companies reference the same tenants full-mesh; per-company reads would
    multiply Graph traffic N-fold and invite throttling).

    disabled/deleted are only read for tenants that are someone's OWN — pure
    group tenants only contribute actives (V1). A failed tenant is recorded
    with read_ok=False; compose_company decides per company whether that is
    fatal (own) or snapshot-incomplete (group).
    """
    data = {}
    for tenant_id in tenant_ids:
        entry = {"active": set(), "disabled": set(), "deleted": set(),
                 "read_ok": False, "error": ""}
        try:
            token = entra.get_graph_token(tenant_id, fconf["client_id"])
            headers = {"Authorization": f"Bearer {token}"}
            entry["active"] = src_users.emails_of(src_users.get_active_members(headers))
            if fconf["enable_former_sync"] and tenant_id in own_union:
                entry["disabled"] = src_users.emails_of(
                    src_users.get_disabled_members(headers))
                if fconf["include_deleted_users"]:
                    entry["deleted"] = src_users.emails_of(
                        src_users.get_deleted_members(headers))
            entry["read_ok"] = True
        except Exception as e:
            entry["error"] = str(e)[:200]
            logger.error("[FORMER] tenant %s read FAILED: %s", tenant_id, e)
            # A tenant that cannot be read ends the run as
            # "incomplete_snapshot", and that one phrase covers revoked
            # consent, a missing federated credential, exhausted throttling
            # and a network fault alike. The log line names the cause but
            # logs age out; without a row here the persistent trail cannot
            # say which of them it was.
            try:
                law.write_lifecycle_event(
                    fconf, "former_tenant_read_failed",
                    tenant_id=tenant_id, details=str(e)[:400])
            except Exception as audit_error:
                logger.error("[FORMER] tenant %s read failure could not be "
                             "recorded: %s", tenant_id, audit_error)
        data[tenant_id] = entry
    return data


def _former_guard_check(fconf: dict, credential, counts: dict,
                        persist_baseline: bool = True) -> tuple:
    """Data-completeness guard (adversary finding 2026-07-24): a tenant that
    answers HTTP 200 with silently incomplete data passes the token gate, so we
    additionally compare per-tenant ACTIVE email counts against the last healthy
    baseline (Table EntraIDState, one global tenant-level record). Returns
    (notes, tripped_tenant_ids) — the caller blocks exactly the companies whose
    own/group sets intersect the tripped tenants. Guard infrastructure errors
    are non-fatal (token gate + own-raise stay in force) but loud.

    persist_baseline: only the TIMER advances the stored baseline. The preview
    endpoint evaluates read-only — a GET must never mutate guard state (and a
    preview storm during replication lag must not touch the baseline).
    """
    import json as _json
    notes = []
    tripped = set()
    try:
        prior = cp.load(fconf["storage_account_name"], credential,
                        f"{_GUARD_SOURCE}:_tenants")
        res = guard_api.evaluate_tenant_counts(
            _json.loads(prior.get("counts_json") or "{}"), counts,
            drop_percent=fconf["former_guard_drop_percent"],
            accept_drop=fconf["former_guard_accept_drop"], label="tenant")
        notes = list(res.notes)
        tripped = set(res.tripped)
        if persist_baseline:
            # Monotonic-upward baseline (see former_guard.py); a tripped tenant
            # keeps its prior healthy count.
            cp.save(fconf["storage_account_name"], credential,
                    f"{_GUARD_SOURCE}:_tenants",
                    {"counts_json": _json.dumps(res.baseline)})
    except Exception as e:
        logger.warning("[FORMER] guard infrastructure error (guard skipped this run): %s", e)
        notes.append(f"guard skipped (infrastructure error: {str(e)[:120]})")
        try:
            # Queryable trace for apply-mode operators: "ran without the
            # completeness guard" must be alertable, not buried in App Insights.
            law.write_lifecycle_event(fconf, "former_guard_skipped",
                                      details=str(e)[:500])
        except Exception as trace_error:
            # Swallowing this silently would defeat the line above: the whole
            # point of the event is that "ran without the completeness guard"
            # is alertable. If the trace itself cannot be written, say so.
            logger.error("[FORMER] could not record former_guard_skipped — "
                         "this run has NO queryable trace of the skipped "
                         "guard: %s", trace_error)
    return notes, tripped


def _company_conf(fconf: dict, row: dict) -> dict:
    """Per-company view of the shared config — the client factory and the
    stores read the socradar_* keys, so overriding them scopes everything
    (client, manual, ownership, audit) to this company."""
    out = dict(fconf)
    out["socradar_company_id"] = row["company_id"]
    out["socradar_api_key"] = row["api_key"]
    out["former_actor_email"] = row["actor_email"]
    out["own_tenant_ids"] = list(row["own_tenants"])
    # Defensive copy: the shallow dict copy would otherwise share this list
    # object across every company conf (latent mutation hazard).
    out["group_tenant_ids"] = list(fconf.get("group_tenant_ids") or [])
    return out


def _former_company_snapshots(fconf: dict, credential,
                              persist_baseline: bool = True) -> dict:
    """Shared read+plan path for the timer AND the preview endpoint — one code
    path, so the preview always shows exactly what the next run would do.

    Topology 2: FORMER_COMPANY_MAP rows; group tenants derived full-mesh.
    Topology 1 (no map): a single row from the legacy scalars — identical
    behavior to the pre-refactor engine. Company isolation: one company's
    failure lands as an error entry in its snap; the others proceed.
    """
    rows, row_errors = companies_api.parse_company_map(
        fconf["company_map_raw"], os.environ)
    topology = "map" if rows else "legacy"
    for err in row_errors:
        logger.error("[FORMER] company map: %s", err)
    if not rows:
        # The legacy scalar row exists for installs that never configured a
        # map. A map that WAS configured but collapsed to zero usable rows
        # (every row dropped — a contested tenant does exactly that) must not
        # fall through to it: that would quietly retarget the run at a company
        # and tenant the operator never named. Configured-but-broken stops here.
        if str(fconf.get("company_map_raw") or "").strip():
            logger.error("[FORMER] FORMER_COMPANY_MAP is set but produced no "
                         "usable rows — refusing the legacy fallback. Errors: %s",
                         "; ".join(row_errors) or "none")
            try:
                law.write_lifecycle_event(
                    fconf, "former_company_map_invalid",
                    details=f"map set, 0 usable rows: {'; '.join(row_errors)[:400]}")
            except Exception as audit_error:
                logger.error("[FORMER] invalid-map event could not be "
                             "recorded: %s", audit_error)
            return {"topology": "invalid-map", "rows": [],
                    "row_errors": row_errors, "guard_notes": [],
                    "tripped": [], "snaps": []}
        rows = [companies_api.legacy_row(fconf)]

    legacy_group = fconf["group_tenant_ids"]
    groups = companies_api.derive_group_tenants(rows, legacy_group)
    tenants, own_union = companies_api.all_tenants(rows, legacy_group)
    tenant_data = _prefetch_tenant_data(fconf, tenants, own_union)

    counts = {tid: len(e["active"]) for tid, e in tenant_data.items() if e["read_ok"]}
    guard_notes, tripped = _former_guard_check(
        fconf, credential, counts, persist_baseline=persist_baseline)

    snaps = []
    for row in rows:
        cid = row["company_id"]
        try:
            conf_c = _company_conf(fconf, row)
            desired, stats, populations = companies_api.compose_company(
                row, groups[cid], tenant_data,
                ruleset_mode=fconf["ruleset_mode"],
                include_deleted=fconf["include_deleted_users"],
                enable_former_sync=fconf["enable_former_sync"],
                enable_cross=fconf["enable_cross_tenant_suppress"])

            # A guard-tripped tenant makes every company reading it incomplete.
            guard_hit = sorted((set(row["own_tenants"]) | set(groups[cid])) & tripped)
            if guard_hit:
                stats["snapshot_complete"] = False

            # Manual entries union AFTER the own-active subtraction: an explicit
            # human entry outranks the automatic safety invariant, and without
            # the union each reconcile would clobber every manual entry.
            manual_store = manual_api.ManualFormerStore(
                fconf["storage_account_name"], credential, cid)
            manual = manual_store.get_set()
            desired |= manual
            stats["manual"] = len(manual)
            stats["desired"] = len(desired)

            client = former_api.build_client(conf_c, credential)
            current = client.get_list()

            # Ownership-aware plan (P0): only Elite-owned records are removal
            # candidates; external records are preserved; incomplete snapshot /
            # bootstrap withhold deletions; caps bound mass changes.
            ownership = ownership_api.TableOwnershipStore(
                fconf["storage_account_name"], credential, cid)
            owned = ownership.owned_among(current)
            plan = planner_api.plan_former_reconcile(
                desired=desired,
                current=current,
                owned=owned,
                snapshot_complete=stats["snapshot_complete"],
                is_bootstrap=ownership.is_bootstrap(),
                max_adds=fconf["former_max_adds"],
                max_removals=fconf["former_max_removals"],
                max_removal_percent=fconf["former_max_removal_percent"],
            )
            snaps.append({"row": row, "conf": conf_c, "desired": desired,
                          "stats": stats, "populations": populations,
                          "manual": manual, "current": current, "owned": owned,
                          "plan": plan, "client": client, "ownership": ownership,
                          "guard_hit": guard_hit, "error": None})
        except Exception as e:
            logger.error("[FORMER] company %s snapshot FAILED: %s", cid, e)
            snaps.append({"row": row, "error": f"{type(e).__name__}: {str(e)[:200]}"})

    return {"topology": topology, "rows": rows, "row_errors": row_errors,
            "guard_notes": guard_notes, "tripped": sorted(tripped), "snaps": snaps}


@app.timer_trigger(
    schedule="%FORMER_SYNC_SCHEDULE%",
    arg_name="timer",
    run_on_startup=_FORMER_RUN_ON_STARTUP
)
def former_employee_sync(timer: func.TimerRequest) -> None:
    logger.info("=== ELITE Former Employee sync started ===")
    if timer.past_due:
        logger.warning("[FORMER] timer past due, running anyway")

    fconf = cfg.load_former()
    if not fconf["enable_former_sync"] and not fconf["enable_cross_tenant_suppress"]:
        logger.info("[FORMER] both features disabled — nothing to do")
        return

    credential = DefaultAzureCredential()
    run = _former_company_snapshots(fconf, credential, persist_baseline=True)
    for note in run["guard_notes"]:
        logger.warning("[FORMER] guard: %s", note)

    summary = []
    for snap in run["snaps"]:
        cid = snap["row"]["company_id"]
        if snap["error"]:
            # Company isolation, and silence is not success: one company's
            # failure is reported per item and must not stop the rest of the loop.
            summary.append((cid, "FAIL", snap["error"]))
            try:
                law.write_lifecycle_event(fconf, "former_company_failed",
                                          details=f"company {cid}: {snap['error']}")
                # Keep the persistent audit table shape uniform: failed
                # companies also get a blocked reconcile-summary row.
                fail_plan = planner_api.FormerPlan(
                    blocked=True, block_reason="company_failed")
                law.write_former_audit(fconf, audit_api.build_former_audit_rows(
                    cid, {"snapshot_complete": False}, fail_plan,
                    {"applied": False, "added": 0, "removed": 0},
                    fconf["former_client_mode"], False))
            except Exception as audit_error:
                # The company already failed; losing its audit row too would
                # leave the failure with no persistent record at all.
                logger.error("[FORMER] company %s failed AND its audit row "
                             "could not be written: %s", cid, audit_error)
            continue

        plan, stats = snap["plan"], snap["stats"]
        for note in plan.notes:
            logger.warning("[FORMER][%s] plan note: %s", cid, note)

        # Real mode demands per-company credentials for mutation; a row missing
        # its actor/key degrades to plan-only (list/preview still work).
        apply_c, apply_note = companies_api.company_effective_apply(
            snap["row"], fconf["former_client_mode"], fconf["former_apply_changes"])
        if apply_note:
            logger.warning("[FORMER][%s] %s", cid, apply_note)

        # Single-writer lease: a manual-endpoint mutation landing
        # mid-apply would corrupt readback accounting. Plan-only runs skip the
        # lock (they mutate nothing); a held lock skips THIS company this tick.
        lock = None
        if apply_c:
            lock = lock_api.TableLeaseLock(
                fconf["storage_account_name"], credential, cid, holder="timer")
            if not lock.acquire():
                logger.warning("[FORMER][%s] lease held (manual op in progress?) — skipped this tick", cid)
                summary.append((cid, "LOCKED", "lease held; retrying next tick"))
                continue

        # Apply (readback-confirmed ledger updates) lives in a pure, unit-tested
        # function; plan-only is the safe default.
        try:
            result = planner_api.execute_former_plan(
                plan, snap["client"], snap["ownership"], apply_c)
        except Exception as apply_error:
            # The isolation rule above covers snapshot failures; apply had no
            # such guard, so a single company raising here took the whole loop
            # down with it — later companies never ran and the per-company
            # status table, printed after the loop, was never printed at all.
            logger.error("[FORMER][%s] apply failed: %s", cid, apply_error)
            summary.append((cid, "FAIL", f"apply: {apply_error}"))
            try:
                law.write_lifecycle_event(
                    fconf, "former_apply_failed",
                    details=f"company {cid}: {str(apply_error)[:400]}")
            except Exception as audit_error:
                logger.error("[FORMER][%s] apply failed AND its lifecycle row "
                             "could not be written: %s", cid, audit_error)
            continue
        else:
            # The lease is not renewed while the apply runs. If it lapsed, a
            # manual operation could have taken over and written to the same
            # list, and these counts describe only our half of that.
            if lock is not None and not lock.still_held():
                logger.error(
                    "[FORMER][%s] the lease expired during apply — another "
                    "writer may have interleaved. Treat this run's counts as "
                    "unconfirmed and re-run a plan-only cycle.", cid)
                try:
                    law.write_lifecycle_event(
                        fconf, "former_lease_lapsed_during_apply",
                        details=f"company {cid}: lease no longer held after apply")
                except Exception as audit_error:
                    logger.error("[FORMER][%s] lapsed lease could not be "
                                 "recorded: %s", cid, audit_error)
        finally:
            if lock is not None:
                lock.release()
        added, removed = result["added"], result["removed"]

        # A mutation that went out but could not be read back leaves the
        # ownership ledger disagreeing with the customer's list. It is not an
        # error we can fix from here, and staying quiet about it is how drift
        # becomes permanent.
        if result.get("unconfirmed_adds") or result.get("unconfirmed_removes"):
            logger.error(
                "[FORMER][%s] %d add(s) and %d removal(s) could not be confirmed: %s. "
                "Ownership for those entries is unrecorded — reconcile will not retire them.",
                cid, result.get("unconfirmed_adds", 0), result.get("unconfirmed_removes", 0),
                result.get("unconfirmed_reason", ""))
            summary.append((cid, "UNCONFIRMED", result.get("unconfirmed_reason", "")))
            try:
                law.write_lifecycle_event(
                    fconf, "former_mutation_unconfirmed",
                    details=(f"company {cid}: adds={result.get('unconfirmed_adds', 0)} "
                             f"removes={result.get('unconfirmed_removes', 0)} "
                             f"{result.get('unconfirmed_reason', '')}"[:400]))
            except Exception as audit_error:
                logger.error("[FORMER][%s] unconfirmed mutation could not be "
                             "recorded: %s", cid, audit_error)

        if plan.blocked:
            logger.error("[FORMER][%s] plan BLOCKED (%s) — no mutation", cid, plan.block_reason)
        elif not apply_c:
            logger.info("[FORMER][%s] plan-only: would add=%d remove=%d preserve=%d",
                        cid, len(plan.add), len(plan.remove), len(plan.preserve))
        else:
            if added < result["add_planned"]:
                logger.error("[FORMER][%s] add readback mismatch: confirmed %d/%d (actor/API?)",
                             cid, added, result["add_planned"])
            if removed < result["remove_planned"]:
                logger.error("[FORMER][%s] remove readback mismatch: confirmed %d/%d",
                             cid, removed, result["remove_planned"])
        if plan.withheld_removals:
            logger.warning("[FORMER][%s] %d removal candidate(s) withheld by guard",
                           cid, len(plan.withheld_removals))

        # Audit trail: COUNTS ONLY in logs; LAW rows carry sha256.
        logger.info(
            "[FORMER][%s] reconcile | mode=%s apply=%s | own_active=%d own_former=%d "
            "sibling_active=%d review_needed=%d manual=%d | desired=%d current=%d owned=%d "
            "preserve=%d | plan_add=%d plan_remove=%d | applied_add=%d applied_remove=%d%s",
            cid, fconf["former_client_mode"], apply_c,
            stats["own_active"], stats["own_former"], stats["sibling_active"],
            stats["review_needed"], stats["manual"], stats["desired"],
            len(snap["current"]), len(snap["owned"]), len(plan.preserve),
            len(plan.add), len(plan.remove), added, removed,
            (" | BLOCKED:" + plan.block_reason) if plan.blocked else "",
        )

        # Persistent audit (option a): hashed per-action rows + summary to
        # SOCRadar_EntraID_Audit_CL. Best-effort — audit must never kill a sync.
        try:
            law.write_former_audit(fconf, audit_api.build_former_audit_rows(
                cid, stats, plan, result, fconf["former_client_mode"], apply_c))
        except Exception as e:
            logger.warning("[FORMER][%s] LAW audit write failed (non-fatal): %s", cid, e)

        status = ("BLOCKED:" + plan.block_reason) if plan.blocked else "OK"
        summary.append((cid, status,
                        f"add={added}/{result['add_planned']} "
                        f"remove={removed}/{result['remove_planned']} "
                        f"preserve={len(plan.preserve)} apply={apply_c}"))

    # Per-company status table — every company reports an explicit outcome.
    for cid, status, detail in summary:
        logger.info("[FORMER] company %s: %s | %s", cid, status, detail)
    failed = [cid for cid, status, _ in summary if status == "FAIL"]
    if failed:
        logger.error("[FORMER] %d/%d company FAILED: %s",
                     len(failed), len(summary), ", ".join(failed))


@app.route(route="former/manual", auth_level=func.AuthLevel.FUNCTION, methods=["POST"])
def former_manual(req: func.HttpRequest) -> func.HttpResponse:
    """Mid-process manual former entry: analyst adds/removes an email on demand
    without waiting for offboarding signals or the next timer tick.

    POST /api/former/manual?code=<function-key>
    body: {"action": "add" | "remove", "emails": [...],
           "company_id": "1234567"}   # optional with a single company; required
                                  # when FORMER_COMPANY_MAP has multiple rows

    Entries land in the FormerManual table AND go to the SOCRadar list
    immediately; the timer sync unions the table into its desired set so
    manual entries survive reconciles (see actions/former_manual.py).
    """
    import json as _json
    try:
        body = req.get_json()
    except ValueError:
        return func.HttpResponse('{"error": "invalid JSON body"}', status_code=400,
                                 mimetype="application/json")

    action = str(body.get("action", "")).strip().lower()
    emails = body.get("emails")
    if action not in ("add", "remove") or not isinstance(emails, list):
        return func.HttpResponse(
            '{"error": "expected {\\"action\\": \\"add|remove\\", \\"emails\\": [...]}"}',
            status_code=400, mimetype="application/json")

    fconf = cfg.load_former()
    rows, _row_errors = companies_api.parse_company_map(
        fconf["company_map_raw"], os.environ)
    if not rows:
        # Same rule as the timer: the legacy scalars are only for installs
        # with no map at all. This is a WRITE endpoint — falling back here
        # would accept a mutation and send it with a company id and API key
        # the operator's map never named.
        if str(fconf.get("company_map_raw") or "").strip():
            return func.HttpResponse(
                _json.dumps({"error": "FORMER_COMPANY_MAP is set but produced "
                                      "no usable rows; fix the map first",
                             "row_errors": _row_errors[:10]}),
                status_code=409, mimetype="application/json")
        rows = [companies_api.legacy_row(fconf)]

    req_company = str(body.get("company_id", "")).strip()
    if req_company:
        row = next((r for r in rows if r["company_id"] == req_company), None)
        if row is None:
            return func.HttpResponse(
                _json.dumps({"error": f"unknown company_id {req_company}"}),
                status_code=400, mimetype="application/json")
    elif len(rows) == 1:
        row = rows[0]
    else:
        return func.HttpResponse(
            _json.dumps({"error": "multiple companies configured — body must "
                                  "include company_id"}),
            status_code=400, mimetype="application/json")

    credential = DefaultAzureCredential()

    # Single-writer lease: refuse to mutate while the timer's
    # apply pass holds this company. 409 = try again after the sync tick.
    lock = lock_api.TableLeaseLock(
        fconf["storage_account_name"], credential, row["company_id"], holder="manual")
    if not lock.acquire():
        return func.HttpResponse(
            _json.dumps({"error": "sync in progress for this company — retry shortly",
                         "company_id": row["company_id"]}),
            status_code=409, mimetype="application/json")
    try:
        store = manual_api.ManualFormerStore(
            fconf["storage_account_name"], credential, row["company_id"])
        client = former_api.build_client(_company_conf(fconf, row), credential)
        result = manual_api.apply_manual(action, emails, store, client)
    finally:
        lock.release()
    result["company_id"] = row["company_id"]
    status = 200 if result["accepted"] else 400
    return func.HttpResponse(_json.dumps(result), status_code=status,
                             mimetype="application/json")


@app.route(route="former/preview", auth_level=func.AuthLevel.FUNCTION, methods=["GET"])
def former_preview(req: func.HttpRequest) -> func.HttpResponse:
    """Read-only endpoint that shows WHO the next reconcile would add/remove,
    computed on demand via the SAME code path as the timer. Never mutates,
    never persists — clear emails live only in this authenticated response
    (the persistent trail is the hashed LAW audit). preserve = count-only.

    GET /api/former/preview?code=<function-key>
    Response: {"topology", "companies": [per-company payload or error],
               "row_errors", "guard_notes"}.
    """
    import json as _json
    try:
        fconf = cfg.load_former()
        credential = DefaultAzureCredential()
        run = _former_company_snapshots(fconf, credential, persist_baseline=False)

        companies = []
        for snap in run["snaps"]:
            cid = snap["row"]["company_id"]
            if snap["error"]:
                companies.append({"company_id": cid, "error": snap["error"]})
                continue
            payloadlet = audit_api.build_preview_payload(
                snap["stats"], snap["populations"], snap["plan"], snap["manual"],
                snap["conf"], run["guard_notes"])
            apply_c, apply_note = companies_api.company_effective_apply(
                snap["row"], fconf["former_client_mode"], fconf["former_apply_changes"])
            payloadlet["effective_apply"] = apply_c
            if apply_note:
                payloadlet["apply_note"] = apply_note
            companies.append(payloadlet)

        payload = {"topology": run["topology"], "companies": companies,
                   "row_errors": run["row_errors"], "guard_notes": run["guard_notes"]}
        return func.HttpResponse(_json.dumps(payload, ensure_ascii=False),
                                 status_code=200, mimetype="application/json")
    except Exception as e:
        logger.error("[FORMER-PREVIEW] failed: %s", e)
        return func.HttpResponse('{"error": "preview failed, see logs"}',
                                 status_code=500, mimetype="application/json")
