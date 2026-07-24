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

logger = logging.getLogger(__name__)
app = func.FunctionApp()

# Time budget per run. Function timeout is 10 min (Y1 Consumption hard cap).
# Leave ~2 min headroom for cleanup (LAW write + checkpoint save).
TIME_BUDGET_SECONDS = 8 * 60

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

    # Get Entra ID tokens — one per configured tenant. The first tenant in the
    # list owns the multi-tenant App Registration + FIC; the others are
    # consented by their admins so a service principal exists for our app_id
    # in each tenant. lookup_user() will try tenants in order, first match wins.
    tenant_headers_map = {}  # ordered dict: tenant_id -> graph_headers
    tenants = cfg.resolve_tenants(conf)

    for permission, reason in _required_graph_permissions(conf):
        logger.info("[ENTRA] Config requires %s — %s", permission, reason)

    if conf["enable_confirm_risky"]:
        logger.info("[ENTRA] EnableConfirmRisky also requires Entra ID P1/P2 licensing")

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
    else:
        logger.info("[ENTRA] Multi-tenant lookup configured for %d tenant(s): %s",
                    len(tenants), ", ".join(tenants))
        for tenant_id in tenants:
            try:
                graph_token = entra.get_graph_token(
                    tenant_id=tenant_id,
                    client_id=conf["client_id"]
                )
                tenant_headers_map[tenant_id] = {
                    "Authorization": f"Bearer {graph_token}",
                    "Content-Type": "application/json"
                }
            except entra.ConsentRevokedError as e:
                logger.error(
                    "[ENTRA] Consent issue for tenant %s (%s): %s — this tenant will be skipped",
                    e.tenant_id, e.aadsts_code, e
                )
                law.write_lifecycle_event(
                    conf,
                    event_type="consent_revoked",
                    tenant_id=e.tenant_id,
                    details=str(e),
                    extra={"aadsts_code": e.aadsts_code}
                )
            except Exception as e:
                logger.error("[ENTRA] Failed to acquire Graph token for tenant %s — this tenant will be skipped: %s",
                             tenant_id, e)
                law.write_lifecycle_event(
                    conf,
                    event_type="token_acquisition_failed",
                    tenant_id=tenant_id,
                    details=str(e)[:500]
                )

        if not tenant_headers_map:
            logger.error("[ENTRA] No tenant produced a usable token — all Entra ID actions will be skipped this run")

    sources_to_run = []
    if conf["enable_botnet_source"]:
        sources_to_run.append("botnet")
    if conf["enable_pii_source"]:
        sources_to_run.append("pii")
    if conf["enable_vip_source"]:
        logger.info("[VIP] Source enabled")
        sources_to_run.append("vip")

    logger.info("Active sources: %s", sources_to_run)

    audit_results = []

    for source_name in sources_to_run:
        # Per-source time budget gate. If function-level elapsed time already
        # exceeded the budget, skip remaining sources so cleanup (LAW write,
        # checkpoint save) can finish within the 10 min function timeout.
        if time.time() - start_time > TIME_BUDGET_SECONDS:
            logger.warning(
                "[%s] Skipped — function time budget (%ds) exhausted before source ran. Will run next timer cycle.",
                source_name.upper(), TIME_BUDGET_SECONDS
            )
            audit_results.append({
                "source": source_name, "total": 0, "employees": 0,
                "found": 0, "not_found": 0, "actions": 0, "errors": 0,
                "duration": 0.0
            })
            continue

        src_start = time.time()
        try:
            result = _process_source(
                source_name=source_name,
                conf=conf,
                credential=credential,
                tenant_headers_map=tenant_headers_map,
                function_start_time=start_time
            )
            result["duration"] = round(time.time() - src_start, 1)
            audit_results.append(result)
        except Exception as e:
            logger.error("[%s] Unhandled error: %s", source_name.upper(), e, exc_info=True)
            audit_results.append({
                "source": source_name, "total": 0, "employees": 0,
                "found": 0, "not_found": 0, "actions": 0, "errors": 1,
                "duration": round(time.time() - src_start, 1)
            })

    # Write audit log
    for r in audit_results:
        audit_summary(
            source=r["source"], total=r["total"], employees=r["employees"],
            found=r["found"], not_found=r["not_found"], actions=r["actions"],
            errors=r["errors"], duration_sec=r.get("duration", 0),
            domain_filtered=r.get("domain_filtered", 0),
        )

    if conf.get("dcr_immutable_id") and conf.get("dcr_endpoint"):
        law.write_audit(conf, audit_results)

    total_duration = round(time.time() - start_time, 1)
    logger.info("=== SOCRadar Entra ID Integration finished in %.1fs ===", total_duration)


def _process_source(source_name: str, conf: dict, credential, tenant_headers_map: dict,
                    function_start_time: float) -> dict:
    """Fetch one source, process each employee credential, return audit dict.

    `tenant_headers_map` is an ordered dict {tenant_id: graph_headers}. For each
    employee, lookup_user is tried against each tenant in order; first match wins
    and all subsequent actions run against that tenant's headers. The tenant in
    which the user was found is recorded as `entra_tenant_id` on the record.

    `function_start_time` is the function invocation start time (used for the
    per-employee time budget check — exits gracefully before function timeout).
    """

    chk = cp.load(conf["storage_account_name"], credential, source_name)

    # Fetch employees from source
    if source_name == "botnet":
        employees = src_botnet.fetch(conf, chk)
    elif source_name == "pii":
        employees = src_pii.fetch(conf, chk)
    elif source_name == "vip":
        employees = src_vip.fetch(conf, chk)
    else:
        # Duration is set by the caller.
        return {"source": source_name, "total": 0, "employees": 0,
                "found": 0, "not_found": 0, "actions": 0, "errors": 0}

    found = not_found = actions = errors = domain_filtered = 0
    records = []
    # Per-tenant 403 counter: if a tenant returns 403 three times in a row,
    # drop it from the lookup map (admin consent missing — no point retrying).
    # Healthy tenants in the same map continue to function.
    tenant_403_counts = {tid: 0 for tid in tenant_headers_map}

    # Extract checkpoint before the loop — it sits on the last record and
    # will be popped from emp before appending to LAW records below.
    new_checkpoint = employees[-1].get("_checkpoint_update", {}) if employees else {}

    for emp in employees:
        # Per-employee time budget check — graceful exit so LAW write +
        # checkpoint save finish within the 10 min function timeout.
        if time.time() - function_start_time > TIME_BUDGET_SECONDS:
            logger.warning(
                "[%s] Time budget (%ds) exhausted mid-source. Stopping early — %d records processed so far. Remaining will resume next run.",
                source_name.upper(), TIME_BUDGET_SECONDS, len(records)
            )
            break

        try:
            email = emp.get("email") or emp.get("user", "")
            if not email:
                continue

            # User lookup in Entra ID (skipped if Graph token unavailable or permissions missing)
            if not conf["enable_user_lookup"]:
                emp["entra_status"] = "skipped_user_lookup_disabled"
                emp["entra_tenant_id"] = ""
                emp["actions_taken"] = []
                emp.pop("_checkpoint_update", None)
                records.append(emp)
                continue

            if not tenant_headers_map:
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
                else:
                    # Non-403 miss (e.g. 404 not_found): tenant is healthy.
                    tenant_403_counts[tenant_id] = 0
                lookup_status = status  # last seen status

            # Fully exhausted lookup map (all tenants 403'd out mid-loop)
            if not tenant_headers_map and user_info is None:
                errors += 1
                logger.warning(
                    "[%s] %s → all tenants exhausted permission errors (403). Marking as lookup_permission_denied. Admin consent likely missing.",
                    source_name.upper(), email
                )
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
                    logger.warning(
                        "[%s] %s → lookup returned 403 (no 200/404 from any tenant). entra_status=lookup_permission_denied",
                        source_name.upper(), email
                    )
                    emp["entra_status"] = "lookup_permission_denied"
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
            emp["entra_account_enabled"] = user_info.get("accountEnabled", True)
            emp["entra_user_id"] = user_info.get("id", "")

            # All subsequent actions use the headers of the tenant where the user was found.
            graph_headers = tenant_headers_map[found_tenant]

            # ROPC validation (only if plaintext password available)
            ropc_result = None
            if conf["enable_ropc"] and emp.get("sanitized", {}).get("is_plaintext"):
                raw_pw = emp.get("sanitized", {}).get("_raw")
                if raw_pw:
                    ropc_result = entra.validate_password_ropc(
                        email=email,
                        password=raw_pw,
                        tenant_id=found_tenant,
                        client_id=conf["client_id"]
                    )
                    del raw_pw  # remove from local scope immediately

            if ropc_result == "valid":
                emp["entra_status"] = "compromised"
                emp["severity"] = "CRITICAL"
            elif ropc_result in ("invalid", "mfa_blocked"):
                emp["severity"] = "MEDIUM"
            else:
                emp["severity"] = "MEDIUM"  # default

            # Take actions
            taken = []
            user_id = emp["entra_user_id"]

            if conf["enable_revoke_session"]:
                ok = entra.revoke_sessions(user_id, graph_headers)
                taken.append("revoke_session" if ok else "revoke_session_failed")
                actions += 1

            if conf["enable_add_to_group"] and conf["security_group_id"]:
                ok = entra.add_to_group(user_id, conf["security_group_id"], graph_headers)
                taken.append("add_to_group" if ok else "add_to_group_failed")
                actions += 1

            if conf["enable_remove_from_group"] and conf["security_group_id"]:
                ok = entra.remove_from_group(user_id, conf["security_group_id"], graph_headers)
                taken.append("remove_from_group" if ok else "remove_from_group_failed")
                actions += 1

            if conf["enable_disable_account"]:
                ok = entra.disable_account(user_id, graph_headers)
                taken.append("disable_account" if ok else "disable_account_failed")
                actions += 1

            if conf["enable_enable_account"]:
                ok = entra.enable_account(user_id, graph_headers)
                taken.append("enable_account" if ok else "enable_account_failed")
                actions += 1

            if conf["enable_password_change"]:
                ok = entra.force_password_change(user_id, graph_headers)
                taken.append("force_password_change" if ok else "force_password_change_failed")
                actions += 1

            if conf["enable_confirm_risky"]:
                ok = entra.confirm_compromised(user_id, graph_headers)
                taken.append("confirm_risky" if ok else "confirm_risky_failed")
                actions += 1

            if conf["enable_force_mfa_reregistration"]:
                mfa_result = entra.force_mfa_reregistration(user_id, graph_headers)
                if mfa_result["permission_denied"]:
                    logger.warning(
                        "[%s] force_mfa_rereg skipped — UserAuthenticationMethod.ReadWrite.All not granted",
                        source_name.upper()
                    )
                    taken.append("force_mfa_rereg_no_permission")
                elif mfa_result["methods_deleted"] > 0:
                    taken.append("force_mfa_rereg")
                elif mfa_result.get("errors"):
                    taken.append("force_mfa_rereg_failed")
                else:
                    # No MFA methods to delete (user only has password method)
                    taken.append("force_mfa_rereg_no_methods")
                emp["mfa_methods_deleted"] = mfa_result["methods_deleted"]
                emp["mfa_methods_skipped"] = mfa_result["methods_skipped"]
                actions += 1

            if conf["enable_create_incident"]:
                sent.create_incident(conf, email, source_name, emp.get("severity", "MEDIUM"), credential=credential)

            # Resolve SOCRadar alarm if user found in Entra ID
            alarm_id = emp.get("alarm_id")
            if conf.get("enable_resolve_alarm") and alarm_id:
                ok = socradar_api.resolve_alarm(
                    api_key=conf["socradar_api_key"],
                    company_id=conf["socradar_company_id"],
                    alarm_id=alarm_id,
                    comment=f"User {email} found in Entra ID — auto-resolved by SOCRadar Entra ID Integration",
                    base_url=conf.get("socradar_base_url", "https://platform.socradar.com")
                )
                taken.append("resolve_alarm" if ok else "resolve_alarm_failed")
                actions += 1

            emp["actions_taken"] = taken
            emp.pop("_checkpoint_update", None)  # internal key — must not reach LAW
            records.append(emp)

        except Exception as e:
            logger.error("[%s] Error processing %s: %s", source_name.upper(), emp.get("email", "?"), e)
            errors += 1

    # Write source records to LAW (skip empty marker records)
    real_records = [r for r in records if not r.get("_empty_marker")]
    if real_records:
        law.write_records(conf, source_name, real_records)

    # Update checkpoint (extracted before the loop above)
    if new_checkpoint:
        cp.save(conf["storage_account_name"], credential, source_name, new_checkpoint)

    # Duration is set by the caller (socradar_entra_id_import) after this returns,
    # so it always reflects real wall-clock time. Not included here to avoid a
    # silent-zero trap if a future caller forgets to overwrite it.
    return {
        "source":     source_name,
        "total":      len(employees),
        "employees":  len([e for e in employees if e.get("is_employee", True)]),
        "found":      found,
        "not_found":  not_found,
        "actions":    actions,
        "errors":     errors,
        "domain_filtered": domain_filtered,
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
        except Exception:
            pass
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
            # Company isolation (SESSIZLIK != BASARI): one company's failure is
            # reported per-item and must not stop the rest of the loop.
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
            except Exception:
                pass
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

        # Single-writer lease (backlog P0): a manual-endpoint mutation landing
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
        finally:
            if lock is not None:
                lock.release()
        added, removed = result["added"], result["removed"]

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

        # Audit trail: COUNTS ONLY in logs (P0 rule 8); LAW rows carry sha256.
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
           "company_id": "330"}   # optional with a single company; required
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

    # Single-writer lease (backlog P0): refuse to mutate while the timer's
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
    """Read-only GOSTER endpoint: WHO the next reconcile would add/remove,
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
