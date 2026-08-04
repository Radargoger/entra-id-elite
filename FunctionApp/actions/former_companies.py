"""
Multi-company (Topology 2) parsing and composition for the Former Employee
sync (pure logic, no I/O).

Topology 2 (2026-07-25, corporate-group example — company A 1234567/te1234567,
B 440/te440, C 550/te550 in ONE deployment): FORMER_COMPANY_MAP is a
JSON app setting with one row per SOCRadar company:

    [{"company_id": "1234567",
      "own_tenants": ["<tenant-guid>", ...],
      "api_key": "...",                    # or api_key_setting: "FORMER_KEY_1234567"
      "actor_email": "person@company.com"},
     ...]

Group tenants are NEVER entered per row — they are DERIVED: a company's group
is the union of every OTHER row's own tenants (full mesh), plus the legacy
global GROUP_TENANT_IDS (tenants whose users should be suppressed everywhere
but that have no SOCRadar company of their own), minus the company's own.

Topology 1 stays the degenerate case: with no FORMER_COMPANY_MAP the caller
builds a single row from the legacy scalar settings; a single-row map derives
an empty mesh (V2-only unless GROUP_TENANT_IDS is set) — the mode switch is
the configuration itself, not a flag.

Every mutation credential is per-company (each company's former list demands
its OWN api_key and its OWN platform actor_email): a row missing either in
real mode is not an error — a missing actor forces plan-only (list/preview
still work); a missing api_key additionally surfaces that company as a
preview error until the key arrives (real mode needs it even to read).
"""

import json
import re

# Storage partition filters interpolate company_id; keep it to a safe charset
# so partition isolation never depends on quoting (adversary note 2026-07-25).
_COMPANY_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def parse_company_map(raw: str, env: dict) -> tuple:
    """Parse FORMER_COMPANY_MAP. Returns (rows, errors).

    A malformed row is dropped with a loud error string (one bad row must not
    take the whole deployment down); malformed JSON drops the whole map.
    api_key_setting indirection lets the actual secret live in its own app
    setting (which can be a Key Vault reference) instead of inside the JSON.
    """
    raw = (raw or "").strip()
    if not raw:
        return [], []
    try:
        data = json.loads(raw)
    except ValueError as e:
        return [], [f"FORMER_COMPANY_MAP is not valid JSON: {str(e)[:120]}"]
    if not isinstance(data, list):
        return [], ["FORMER_COMPANY_MAP must be a JSON array of company rows"]

    rows, errors = [], []
    seen = set()
    for i, item in enumerate(data):
        if not isinstance(item, dict):
            errors.append(f"row {i}: not an object — dropped")
            continue
        # Accept the ARM createUiDefinition EditableGrid field names as aliases
        # (companyId/tenantIds/apiKey/actorEmail); tenants may arrive as a CSV
        # string from a grid text column. Converting here keeps the ARM template
        # a pass-through (string(FormerCompanies)) instead of an object-mapping
        # exercise in template language.
        company_id = str(item.get("company_id") or item.get("companyId") or "").strip()
        raw_tenants = item.get("own_tenants") or item.get("tenantIds") or []
        if isinstance(raw_tenants, str):
            raw_tenants = raw_tenants.split(",")
        own = [str(t).strip() for t in raw_tenants if str(t).strip()]
        if not company_id:
            errors.append(f"row {i}: company_id missing — dropped")
            continue
        if not _COMPANY_ID_RE.match(company_id):
            errors.append(f"row {i}: company_id has unsafe characters — dropped")
            continue
        if not own:
            errors.append(f"row {i} (company {company_id}): own_tenants missing — dropped")
            continue
        if company_id in seen:
            errors.append(f"row {i}: duplicate company_id {company_id} — dropped")
            continue
        seen.add(company_id)

        api_key = str(item.get("api_key") or item.get("apiKey") or "").strip()
        # Both spellings, like every other field here. Accepting apiKey but not
        # apiKeySetting failed silently: the row kept no key and no reference,
        # so it passed validation and the company was simply never read.
        key_setting = str(item.get("api_key_setting")
                          or item.get("apiKeySetting") or "").strip()
        if not api_key and key_setting:
            api_key = str((env or {}).get(key_setting) or "").strip()
            if not api_key:
                errors.append(f"company {company_id}: api_key_setting '{key_setting}' "
                              f"is empty or unset")

        rows.append({
            "company_id": company_id,
            "own_tenants": list(dict.fromkeys(own)),  # dedupe, keep order
            "api_key": api_key,
            "actor_email": str(item.get("actor_email") or item.get("actorEmail")
                               or "").strip().lower(),
        })

    # A tenant may belong to exactly one company. Two rows claiming the same
    # tenant would search one directory for both companies' findings and act in
    # it for both — the isolation this map exists to enforce, quietly gone. The
    # portal grid cannot prevent it either (its regex checks each cell's GUID
    # shape, not uniqueness across rows). Ambiguous ownership cannot be
    # resolved by picking a winner, so every row touching the shared tenant is
    # dropped, loudly.
    tenant_owners = {}
    for row in rows:
        for tid in row["own_tenants"]:
            tenant_owners.setdefault(tid.lower(), []).append(row["company_id"])
    contested = {tid: owners for tid, owners in tenant_owners.items()
                 if len(owners) > 1}
    if contested:
        dropped = sorted({cid for owners in contested.values() for cid in owners})
        for tid, owners in sorted(contested.items()):
            errors.append(f"tenant {tid} is claimed by companies "
                          f"{', '.join(sorted(owners))} — a tenant can have "
                          f"only one owner; all of them dropped")
        rows = [r for r in rows if r["company_id"] not in dropped]
    return rows, errors


def legacy_row(fconf: dict) -> dict:
    """Topology 1 degenerate case: one row from the legacy scalar settings."""
    return {
        "company_id": str(fconf.get("socradar_company_id") or "").strip(),
        "own_tenants": list(fconf.get("own_tenant_ids") or []),
        "api_key": fconf.get("socradar_api_key") or "",
        "actor_email": (fconf.get("former_actor_email") or "").strip().lower(),
    }


def derive_group_tenants(rows: list, legacy_group=None) -> dict:
    """company_id -> group tenant list (full mesh + legacy extras, minus own)."""
    legacy_group = [t for t in (legacy_group or []) if t]
    out = {}
    for row in rows:
        own = set(row["own_tenants"])
        group = []
        for other in rows:
            if other["company_id"] == row["company_id"]:
                continue
            group.extend(other["own_tenants"])
        group.extend(legacy_group)
        out[row["company_id"]] = [t for t in dict.fromkeys(group) if t not in own]
    return out


def all_tenants(rows: list, legacy_group=None) -> tuple:
    """(every tenant to prefetch, union of all OWN tenants). Own tenants need
    disabled+deleted reads too; pure group tenants only need actives."""
    own_union, everything = [], []
    for row in rows:
        own_union.extend(row["own_tenants"])
        everything.extend(row["own_tenants"])
    everything.extend(legacy_group or [])
    return list(dict.fromkeys(everything)), set(own_union)


def company_effective_apply(row: dict, client_mode: str, global_apply: bool) -> tuple:
    """(apply: bool, note: str|None). Real mode demands per-company credentials
    for mutation; a row missing them degrades to plan-only, never to a crash."""
    if not global_apply:
        return False, None
    if client_mode == "real":
        if not row.get("api_key"):
            return False, (f"company {row['company_id']}: api_key missing — "
                           f"forced plan-only")
        if not row.get("actor_email"):
            return False, (f"company {row['company_id']}: actor_email missing — "
                           f"forced plan-only (list/preview still work)")
    return True, None


def compose_company(row: dict, group_tenants: list, tenant_data: dict, *,
                    ruleset_mode: str, include_deleted: bool,
                    enable_former_sync: bool, enable_cross: bool) -> tuple:
    """Per-company formula from prefetched tenant data. Returns
    (desired, stats, populations) — the same shapes the single-company
    _compute_desired_former_set produced.

    Fail-closed per invariant: any OWN tenant that was not fully read raises
    (a partial own-active set would let active employees leak into desired);
    an unread GROUP tenant only marks the snapshot incomplete (the planner
    then withholds all mutation for this company).
    """
    # No spelling fix-up here on purpose. The only value this function reads is
    # "strict", so normalising anything else changed nothing observable and read
    # as a guarantee it was not providing. The legacy "standart" spelling that
    # running installations still send is normalised once, in config.load_former,
    # which is where it can be tested.

    for tid in row["own_tenants"]:
        entry = tenant_data.get(tid)
        if entry is None or not entry.get("read_ok"):
            err = (entry or {}).get("error", "not prefetched")
            raise RuntimeError(f"own tenant {tid} unreadable ({err}) — aborting "
                               f"company {row['company_id']} (safety invariant)")

    own_active, own_disabled, own_deleted = set(), set(), set()
    review_needed = 0
    for tid in row["own_tenants"]:
        entry = tenant_data[tid]
        own_active |= entry["active"]
        if enable_former_sync:
            if ruleset_mode == "strict":
                review_needed += len(entry["disabled"])
            else:
                own_disabled |= entry["disabled"]
            if include_deleted:
                own_deleted |= entry["deleted"]

    sibling_active = set()
    group = group_tenants if enable_cross else []
    group_read = 0
    for tid in group:
        entry = tenant_data.get(tid)
        if entry is not None and entry.get("read_ok"):
            sibling_active |= entry["active"]
            group_read += 1
    group_complete = (group_read == len(group))

    own_former = own_disabled | own_deleted
    desired = (sibling_active | own_former) - own_active
    stats = {
        "company_id": row["company_id"],
        "own_tenants": len(row["own_tenants"]),
        "group_tenants_read": group_read,
        "group_tenants_configured": len(group),
        "own_active": len(own_active),
        "own_former": len(own_former),
        "sibling_active": len(sibling_active),
        "review_needed": review_needed,
        "desired": len(desired),
        "snapshot_complete": group_complete,
    }
    populations = {
        "own_disabled": own_disabled,
        "own_deleted": own_deleted,
        "sibling_active": sibling_active,
    }
    return desired, stats, populations
