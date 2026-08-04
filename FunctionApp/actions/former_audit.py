"""
Former Employee observability builders (pure logic, no I/O).

Two consumers, two PII postures — decided 2026-07-25 (option a):

  * build_former_audit_rows -> PERSISTENT Log Analytics audit
    (SOCRadar_EntraID_Audit_CL). Emails as sha256 hashes only. Answers "what happened,
    when, how many, which record (by hash)" forever.

  * build_preview_payload   -> EPHEMERAL authenticated GET response.
    Answers "show me the deactivated users": names WHO would be added or
    removed, in the clear, computed on demand and never stored. `preserve`
    (external records, e.g. a customer's own list) is COUNT-ONLY — the
    plan never touches those and their addresses are not ours to display.

Both builders are pure so the shapes are locked by unit tests without Azure.
"""

from datetime import datetime, timezone

from actions.former_ownership import email_hash

# Preview lists are operator-facing; cap them so a huge tenant cannot turn the
# response into a data dump. The counts are always exact.
PREVIEW_LIST_CAP = 200


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_former_audit_rows(company_id: str, stats: dict, plan, result: dict,
                            mode: str, apply_changes: bool) -> list:
    """Rows for SOCRadar_EntraID_Audit_CL: one reconcile summary + one row per
    planned action (hashed email). Safe to call on blocked/plan-only runs."""
    ts = _now_iso()
    company_id = str(company_id)

    rows = [{
        "TimeGenerated":  ts,
        "source":         "former_sync",
        "event_type":     "former_reconcile_summary",
        "company_id":     company_id,
        "mode":           mode,
        "apply":          bool(apply_changes),
        "blocked":        bool(plan.blocked),
        "block_reason":   plan.block_reason,
        "snapshot_complete": bool(stats.get("snapshot_complete", False)),
        "own_active":     int(stats.get("own_active", 0)),
        "own_former":     int(stats.get("own_former", 0)),
        "sibling_active": int(stats.get("sibling_active", 0)),
        "manual":         int(stats.get("manual", 0)),
        "desired":        int(stats.get("desired", 0)),
        "preserve":       len(plan.preserve),
        "add_planned":    len(plan.add),
        "remove_planned": len(plan.remove),
        "withheld":       len(plan.withheld_removals),
        "added":          int(result.get("added", 0)),
        "removed":        int(result.get("removed", 0)),
        "notes":          "; ".join(plan.notes)[:1000],
    }]

    applied = bool(result.get("applied", False))
    for event_type, emails, was_applied in (
        ("former_add", plan.add, applied),
        ("former_remove", plan.remove, applied),
        ("former_removal_withheld", plan.withheld_removals, False),
    ):
        for email in emails:
            rows.append({
                "TimeGenerated": ts,
                "source":        "former_sync",
                "event_type":    event_type,
                "company_id":    company_id,
                "email_sha256":  email_hash(email),
                "applied":       was_applied,
            })
    return rows


def _capped(emails) -> dict:
    """Exact count + a capped, sorted listing (truncated flag when capped)."""
    items = sorted(emails)
    return {
        "count": len(items),
        "emails": items[:PREVIEW_LIST_CAP],
        "truncated": len(items) > PREVIEW_LIST_CAP,
    }


def build_preview_payload(stats: dict, populations: dict, plan, manual: set,
                          fconf: dict, guard_notes: list) -> dict:
    """Authenticated GET former/preview response: WHO the reconcile would touch,
    before any mutation. Ephemeral by contract — callers must not persist it."""
    return {
        "generated_at": _now_iso(),
        "company_id": str(fconf.get("socradar_company_id", "")),
        "mode": fconf.get("former_client_mode", ""),
        "apply_changes": bool(fconf.get("former_apply_changes", False)),
        "ruleset_mode": fconf.get("ruleset_mode", ""),
        "snapshot_complete": bool(stats.get("snapshot_complete", False)),
        "guard_notes": list(guard_notes or []),
        "populations": {
            # Shown by name: the disabled/deleted/sibling people behind the plan.
            "own_disabled": _capped(populations.get("own_disabled", ())),
            "own_deleted":  _capped(populations.get("own_deleted", ())),
            "sibling_active": _capped(populations.get("sibling_active", ())),
            # own_active is the safety set; counts suffice (it is never former).
            "own_active_count": int(stats.get("own_active", 0)),
        },
        "manual": _capped(manual or set()),
        "plan": {
            "add": _capped(plan.add),
            "remove": _capped(plan.remove),
            "withheld_removals": _capped(plan.withheld_removals),
            # External records (not Elite-owned, never auto-deleted). Their
            # addresses are not ours to display — count only.
            "preserve_count": len(plan.preserve),
            "blocked": bool(plan.blocked),
            "block_reason": plan.block_reason,
            "notes": list(plan.notes),
        },
    }
