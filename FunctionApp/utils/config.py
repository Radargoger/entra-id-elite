"""
Configuration loader — reads all settings from Azure App Settings (environment variables).
Validates required fields and provides typed accessors.
"""

import logging
import os

_logger = logging.getLogger("socradar.entra.config")


def _get(key: str, default=None, required: bool = False):
    val = os.environ.get(key, default)
    if required and not val:
        raise EnvironmentError(f"Required App Setting missing: {key}")
    return val


def _bool(key: str, default: bool = False) -> bool:
    raw = os.environ.get(key, "")
    val = raw.strip().lower()
    if val in ("true", "1", "yes", "on"):
        return True
    if val in ("false", "0", "no", "off"):
        return False
    if val:
        # Several of these switches arm directory mutations and default to on.
        # A value we do not recognise used to fall through to that default, so
        # "ENABLE_REVOKE_SESSION=disabled" left the action ARMED with only an
        # error log to say so. We cannot guess what was meant, but between the
        # two wrong guesses only one changes somebody's directory: an
        # unrecognised value now reads as False. Off is the state every switch
        # here can safely be in.
        _logger.error(
            "App Setting %s has an unrecognised value %r; treating it as "
            "false. Use true or false.", key, raw.strip())
        return False
    return default


def _int(key: str, default: int = 0, on_invalid: int = None) -> int:
    """on_invalid: what an unparseable value becomes. Caps pass 0 so that a
    typo in a mutation ceiling closes the gate rather than silently restoring
    the default (a broken FORMER_MAX_REMOVALS meant 100, not 0)."""
    raw = os.environ.get(key, "")
    if not raw.strip():
        return default
    try:
        return int(raw)
    except (ValueError, TypeError):
        fallback = default if on_invalid is None else on_invalid
        _logger.error(
            "App Setting %s has a non-numeric value %r; using %d.",
            key, raw.strip(), fallback)
        return fallback


def _list(key: str, default: str = "") -> list:
    """Parse a comma-separated env value into a list of stripped non-empty strings."""
    raw = os.environ.get(key, default).strip()
    if not raw:
        return []
    return [x.strip() for x in raw.split(",") if x.strip()]


def resolve_tenants(conf: dict) -> list:
    """Return ordered list of tenant IDs to query for Graph lookups.

    Priority:
      1. ENTRA_TENANT_IDS (CSV)       — multi-tenant mode
      2. ENTRA_TENANT_ID (single)     — single-tenant backward compat
      3. []                           — Graph lookups disabled
    """
    if conf.get("tenant_ids"):
        return list(conf["tenant_ids"])
    if conf.get("tenant_id"):
        return [conf["tenant_id"]]
    return []


def load() -> dict:
    """Load and validate all configuration. Raises EnvironmentError on missing required settings."""
    user_lookup = _bool("ENABLE_USER_LOOKUP", True)

    # Validate tenant config when user_lookup is enabled: at least one of
    # ENTRA_TENANT_IDS (CSV) or ENTRA_TENANT_ID (single) must be set.
    if user_lookup:
        tenant_ids_raw = os.environ.get("ENTRA_TENANT_IDS", "").strip()
        tenant_id_raw = os.environ.get("ENTRA_TENANT_ID", "").strip()
        if not tenant_ids_raw and not tenant_id_raw:
            raise EnvironmentError(
                "Required App Setting missing: ENTRA_TENANT_IDS (or legacy ENTRA_TENANT_ID)"
            )

    conf = {
        # SOCRadar API
        "socradar_base_url":   _get("SOCRADAR_BASE_URL", default="https://platform.socradar.com"),
        "socradar_api_key":    _get("SOCRADAR_API_KEY", required=True),
        "socradar_company_id": _get("SOCRADAR_COMPANY_ID", required=True),

        # Source toggles
        "enable_botnet_source": _bool("ENABLE_BOTNET_SOURCE", True),
        "enable_pii_source":      _bool("ENABLE_PII_SOURCE", True),
        "enable_vip_source":      _bool("ENABLE_VIP_SOURCE", False),

        # Entra ID — identifiers only, NO secret.
        # Graph auth uses Workload Identity Federation: UAMI → App Registration.
        # Permissions managed in portal (App Registration → API permissions).
        #
        # Multi-tenant: ENTRA_TENANT_IDS (CSV) is the primary path; the customer's
        # multi-tenant App Registration lives in the first ("primary") tenant and
        # is consented in the others. Each lookup tries tenants in order, first
        # match wins. ENTRA_TENANT_ID (single) is retained for backward compat —
        # see resolve_tenants() in this module.
        "tenant_ids":    _list("ENTRA_TENANT_IDS"),
        "tenant_id":     _get("ENTRA_TENANT_ID", default=""),
        "client_id":     _get("ENTRA_CLIENT_ID", required=user_lookup),

        # Verified-domain allowlist (optional). When non-empty, only records whose
        # email domain matches one of these is forwarded to Microsoft Graph; others
        # are written to LAW with entra_status="skipped_domain_allowlist". Empty
        # list disables filtering (current behavior). Case-insensitive exact match
        # — lowercased on load so the per-record comparison stays cheap.
        "verified_domains": [d.lower() for d in _list("ENTRA_ID_VERIFIED_DOMAINS")],

        # Action toggles
        "enable_user_lookup":       user_lookup,
        "enable_ropc":              _bool("ENABLE_ROPC", False),
        "enable_revoke_session":    _bool("ENABLE_REVOKE_SESSION", True),
        "enable_add_to_group":      _bool("ENABLE_ADD_TO_GROUP", True),
        "enable_remove_from_group": _bool("ENABLE_REMOVE_FROM_GROUP", False),
        "enable_password_change":   _bool("ENABLE_PASSWORD_CHANGE", False),
        "enable_disable_account":   _bool("ENABLE_DISABLE_ACCOUNT", False),
        "enable_enable_account":    _bool("ENABLE_ENABLE_ACCOUNT", False),
        "enable_confirm_risky":     _bool("ENABLE_CONFIRM_RISKY", False),
        "enable_force_mfa_reregistration": _bool("ENABLE_FORCE_MFA_REREGISTRATION", False),
        "enable_create_incident":   _bool("ENABLE_CREATE_INCIDENT", False),
        "enable_resolve_alarm":     _bool("ENABLE_RESOLVE_ALARM", False),
        "security_group_id":        _get("SECURITY_GROUP_ID", default=""),

        # Directory mutations are gated twice, independently of the toggles above.
        # apply is the only mode that touches Entra ID; plan resolves every action
        # and records it without calling Graph.
        "entra_action_mode": (_get("ENTRA_ACTION_MODE", default="plan") or "plan").lower(),
        # Absolute ceiling per run. A leak feed that suddenly returns thousands of
        # records must not turn into thousands of account mutations.
        "entra_max_actions_per_run": _int("ENTRA_MAX_ACTIONS_PER_RUN", 50, on_invalid=0),
        # How long the idempotency ledger keeps a window. Rows older than this
        # cannot be reached by any re-read, so keeping them only grows the
        # table. Floored in action_ledger.cutoff_date, not here, so the floor
        # holds whatever the setting says.
        "leak_ledger_retention_days": _int("LEAK_LEDGER_RETENTION_DAYS", 90),

        # Company map (Topology 2). When set, the import loops over its rows and
        # each company is searched ONLY in its own tenants.
        "company_map_raw": _get("FORMER_COMPANY_MAP", default=""),

        # Pages pulled from a feed in one run. Keep it small enough that the
        # records fetched can also be looked up in the same run.
        "max_pages_per_run": _int("MAX_PAGES_PER_RUN", 50),

        # No password policy switch here on purpose: whether a credential
        # arrives masked or in the clear is set per company in the SOCRadar
        # platform, upstream of this app. A second switch on this side could
        # only contradict the source.

        # Log Analytics (read-only — used by tests/diagnostics, not for ingestion)
        "workspace_id":  _get("WORKSPACE_ID", default=""),

        # DCR-based Logs Ingestion API (replaces legacy HTTP Data Collector API).
        # See: https://learn.microsoft.com/azure/azure-monitor/logs/custom-logs-migrate
        "dcr_immutable_id": _get("DCR_IMMUTABLE_ID", required=True),
        "dcr_endpoint":     _get("DCR_ENDPOINT", required=True),

        # Microsoft Sentinel (optional, only if create_incident=true)
        "subscription_id":          _get("SUBSCRIPTION_ID", default=""),
        "workspace_name":           _get("WORKSPACE_NAME", default=""),
        "workspace_location":       _get("WORKSPACE_LOCATION", default=""),
        "workspace_resource_group": _get("WORKSPACE_RESOURCE_GROUP", default=""),

        # Storage (for checkpoint)
        "storage_account_name": _get("STORAGE_ACCOUNT_NAME", required=True),

        # Schedule
        "initial_lookback_minutes": _int("INITIAL_LOOKBACK_MINUTES", 43200),
        "initial_start_date": _get("INITIAL_START_DATE", default=""),
    }

    return conf


def load_former() -> dict:
    """Configuration for the Former Employee sync (elite).

    Deliberately independent from load(): the former sync has no DCR/LAW
    hard dependency, so an elite deployment can run former-sync-only without
    ingestion infrastructure.

    Tenant model:
      OWN_TENANT_IDS   — tenants that ARE this company ("ours"). Required.
      GROUP_TENANT_IDS — sibling tenants of the same corporate group whose
                         users are unrelated to this company. Optional; empty
                         means single-tenant mode (cross-tenant suppression off).

    Desired former set =
        (active Members of GROUP tenants)            [cross-tenant, V1]
      U (disabled+deleted Members of OWN tenants)    [own leavers,   V2]
      - (active Members of OWN tenants)              [never suppress an active own employee]
    """
    # Topology 2: FORMER_COMPANY_MAP (JSON rows) supersedes the legacy scalars;
    # with a map present the per-row credentials carry the requirements and the
    # legacy scalars become optional (parse + validation: actions/former_companies).
    company_map_raw = _get("FORMER_COMPANY_MAP", default="")
    has_map = bool((company_map_raw or "").strip())

    own = _list("OWN_TENANT_IDS")
    if not own:
        # Backward-friendly fallback: reuse ENTRA_TENANT_IDS / ENTRA_TENANT_ID as "own".
        own = _list("ENTRA_TENANT_IDS")
        if not own:
            single = _get("ENTRA_TENANT_ID", default="")
            own = [single] if single else []
    if not own and not has_map:
        raise EnvironmentError("Required App Setting missing: OWN_TENANT_IDS")

    former_client_mode = (_get("FORMER_CLIENT_MODE", default="mock") or "mock").lower()

    conf_former = {
        "company_map_raw":  company_map_raw,
        "own_tenant_ids":   own,
        # Kept verbatim. Filtering here against `own` looked like it stopped
        # someone listing their own tenant as a group tenant, but `own` falls
        # back to the deployment tenant when the template writes no
        # OWN_TENANT_IDS -- which it never does. A holding tenant entered in the
        # form was therefore dropped whenever the app was deployed into that
        # same tenant, and dropped silently: with nothing in the list,
        # group_read == len(group) is 0 == 0, so the snapshot still counted as
        # complete and removals were not withheld. Nothing looked wrong.
        # The exclusion belongs per company, in
        # actions/former_companies.derive_group_tenants, which knows which
        # tenants each row owns. One caveat, because an earlier version of this
        # comment overstated the fix: in legacy single-company mode (no
        # FORMER_COMPANY_MAP) the synthesised row's own tenants come from this
        # same fallback, so a holding tenant that is also the deployment tenant
        # is still dropped there, and still silently. Every deployment the
        # portal produces carries a map (the grid requires at least one row with
        # a tenant), and without a map the former sync does not run at all
        # because the template writes SOCRADAR_COMPANY_ID as a placeholder. The
        # remaining case is a hand-built CLI deployment.
        "group_tenant_ids": _list("GROUP_TENANT_IDS"),
        "client_id":        _get("ENTRA_CLIENT_ID", required=True),

        "enable_former_sync":           _bool("ENABLE_FORMER_SYNC", True),
        "enable_cross_tenant_suppress": _bool("ENABLE_CROSS_TENANT_SUPPRESS", True),
        "include_deleted_users":        _bool("INCLUDE_DELETED_USERS", True),
        # standard: disabled Member without HR signal counts as former (K4a).
        # strict:   such records are only logged as review-needed, not sent (K4b).
        "ruleset_mode": (_get("RULESET_MODE", default="standard") or "standard").lower(),

        # SOCRadar former list client — paths per DRP Former Employees API
        # (openapi drp_former_employeeapi.yaml, 2026-07-16).
        "former_client_mode": former_client_mode,
        "socradar_base_url":   _get("SOCRADAR_BASE_URL", default="https://platform.socradar.com"),
        "socradar_api_key":    _get("SOCRADAR_API_KEY",
                                    required=(former_client_mode == "real" and not has_map)),
        "socradar_company_id": _get("SOCRADAR_COMPANY_ID", required=not has_map, default=""),
        "former_list_path":   _get("FORMER_LIST_PATH", default="/api/company/{company_id}/dark-web-monitoring/former-employees"),
        "former_add_path":    _get("FORMER_ADD_PATH", default="/api/company/{company_id}/dark-web-monitoring/add-former-employee"),
        "former_remove_path": _get("FORMER_REMOVE_PATH", default="/api/company/{company_id}/dark-web-monitoring/delete-former-employee"),
        "former_batch_size":  _int("FORMER_BATCH_SIZE", 100),
        # HTTP read timeout (s). A large former list behind Cloudflare exceeds
        # a 30s read, so the default is 60.
        "former_http_timeout": _int("FORMER_HTTP_TIMEOUT", 60),
        # Acting user's email — the API requires an "email" field on every
        # add/delete call and validates it belongs to the company on the
        # SOCRadar platform. Required in real mode.
        "former_actor_email": _get("FORMER_ACTOR_EMAIL",
                                   required=(former_client_mode == "real" and not has_map),
                                   default=""),

        # Storage (mock client + checkpoint)
        "storage_account_name": _get("STORAGE_ACCOUNT_NAME", required=True),

        # Safety: the reconcile is ownership
        # aware and plan-only by default. Real deletion never happens unless
        # apply is explicitly turned on AND the snapshot is complete AND the plan
        # is under the caps. These defaults keep an elite deployment safe even
        # with real credentials (contrast: the Taegis bridge shipped apply-all;
        # elite is production-blocked, so its safe default is plan-only).
        "former_apply_changes":      _bool("FORMER_APPLY_CHANGES", False),
        "former_max_adds":           _int("FORMER_MAX_ADDS", 500, on_invalid=0),
        "former_max_removals":       _int("FORMER_MAX_REMOVALS", 100, on_invalid=0),
        "former_max_removal_percent": _int("FORMER_MAX_REMOVAL_PERCENT", 50, on_invalid=0),

        # Data-completeness guard (actions/former_guard.py): a per-tenant email
        # count dropping to 0 or by more than drop_percent vs the last healthy
        # run marks the snapshot incomplete (mutation=0). ACCEPT_DROP adopts the
        # new counts as baseline for one run (real shrinkage, operator call).
        "former_guard_drop_percent": _int("FORMER_GUARD_DROP_PERCENT", 50),
        "former_guard_accept_drop":  _bool("FORMER_GUARD_ACCEPT_DROP", False),

        # Optional persistent audit (SOCRadar_EntraID_Audit_CL via DCR). Absent
        # => audit rows are skipped; the former sync has no LAW hard dependency.
        "dcr_immutable_id": _get("DCR_IMMUTABLE_ID", default=""),
        "dcr_endpoint":     _get("DCR_ENDPOINT", default=""),
    }

    # "standart" was the canonical spelling in earlier releases and is still the
    # value set in running installations. Accept it and normalise, so upgrading
    # to this build does not silently change what those deployments do.
    # Anything else is a typo, and a typo must not pick the looser mode: an
    # unknown value used to fall through to standard behaviour (disabled users
    # sent to the former list). Unknown now reads as strict — log-and-review,
    # no list writes for those records — until someone fixes the setting.
    ruleset_mode = conf_former["ruleset_mode"]
    if ruleset_mode == "standart":
        ruleset_mode = "standard"
    elif ruleset_mode not in ("standard", "strict"):
        _logger.error(
            "RULESET_MODE has an unrecognised value %r; running as 'strict' "
            "(log-only for disabled users) until it is corrected.", ruleset_mode)
        ruleset_mode = "strict"
    conf_former["ruleset_mode"] = ruleset_mode

    return conf_former
