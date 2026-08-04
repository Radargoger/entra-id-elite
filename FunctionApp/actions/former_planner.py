"""
Ownership-aware reconcile planner for the Former Employee sync (pure logic).

Why this module exists:
the old reconcile computed

    to_remove = current - desired

which treats the ENTIRE remote SOCRadar former list as Elite-owned. A record
added by the SOCRadar UI or another integration that Elite's desired set does
not contain would be DELETED. That is the headline reason the elite former sync
is production-blocked.

Correct model:

    C = current      remote SOCRadar former list
    O = owned        records Elite created AND confirmed via readback (ledger)
    D = desired      from a COMPLETE snapshot

    add      = D - C
    remove   = (O ∩ C) - D      # only our own records are removal candidates
    preserve = C - O            # external records — never auto-deleted

Safety gates layered on top (all fail CLOSED):
  * incomplete snapshot            -> mutation count 0 (blocked)
  * bootstrap / first real run     -> removals forced to 0
  * absolute add / removal caps    -> over-cap blocks the whole side, no partial
  * removal percentage cap         -> guards against mass deletion

The planner does no I/O and never raises on business conditions; it returns a
plan describing exactly what a caller may do, plus the reasons it withheld work.
"""

from dataclasses import dataclass, field


@dataclass
class FormerPlan:
    add: list = field(default_factory=list)
    remove: list = field(default_factory=list)
    preserve: list = field(default_factory=list)
    # Records that would be removal candidates by the formula but were withheld
    # by a guard (bootstrap, caps). Surfaced for audit, never auto-deleted.
    withheld_removals: list = field(default_factory=list)
    blocked: bool = False
    block_reason: str = ""
    notes: list = field(default_factory=list)

    def mutating(self) -> bool:
        return bool(self.add or self.remove)


def plan_former_reconcile(
    *,
    desired: set,
    current: set,
    owned: set,
    snapshot_complete: bool,
    is_bootstrap: bool,
    max_adds=None,
    max_removals=None,
    max_removal_percent: int = 100,
) -> FormerPlan:
    """Compute a safe reconcile plan.

    Args:
      desired:  emails the policy wants former (from a complete snapshot).
      current:  emails currently on the remote SOCRadar former list.
      owned:    subset of `current` that Elite owns (ledger, readback-confirmed).
                MUST already be intersected with current by the caller/store.
      snapshot_complete: every own AND configured group tenant read fully.
      is_bootstrap: first real run / empty ownership ledger. Removals forced 0.
      max_adds / max_removals: absolute caps. None = no cap; 0 = none allowed
                (e.g. max_removals=0 withholds every removal). Over-cap withholds
                that mutation side entirely — never a partial mutation.
      max_removal_percent: removals may not exceed this %% of `current`.

    Returns a FormerPlan. When blocked, add and remove are both empty.
    """
    desired = {e for e in (desired or set()) if e}
    current = {e for e in (current or set()) if e}
    owned = {e for e in (owned or set()) if e} & current

    preserve = sorted(current - owned)

    # Hard gate: an incomplete snapshot can under-produce `desired`, which would
    # turn owned-but-not-desired records into false removal candidates and also
    # miss adds. Withhold ALL mutation.
    if not snapshot_complete:
        return FormerPlan(
            preserve=preserve,
            blocked=True,
            block_reason="incomplete_snapshot",
            notes=["one or more own/group tenants were not fully read; mutation=0"],
        )

    add = sorted(desired - current)
    remove_candidates = sorted((owned & current) - desired)

    plan = FormerPlan(preserve=preserve)

    # Bootstrap: the ledger is empty, so nothing is provably owned yet. Never
    # delete on the first real run; adds are allowed (they become owned after
    # readback). Any formula-derived removals are withheld for audit.
    if is_bootstrap:
        plan.withheld_removals = remove_candidates
        remove_candidates = []
        if plan.withheld_removals:
            plan.notes.append(
                f"bootstrap run: {len(plan.withheld_removals)} removal candidate(s) withheld (MAX_REMOVALS=0)")

    # Absolute add cap: over-cap blocks the ADD side entirely (no partial add
    # that could look complete). Removals are unaffected. None = no cap.
    if max_adds is not None and len(add) > max_adds:
        plan.notes.append(f"add cap exceeded ({len(add)} > {max_adds}); adds withheld")
        add = []

    # Removal caps: absolute and percentage. Over either cap withholds ALL
    # removals (never a partial delete). None = no absolute cap; 0 = none allowed.
    if remove_candidates:
        over_abs = max_removals is not None and len(remove_candidates) > max_removals
        pct = (len(remove_candidates) * 100) / len(current) if current else 0
        over_pct = pct > max_removal_percent
        if over_abs or over_pct:
            plan.withheld_removals = remove_candidates
            plan.notes.append(
                f"removal cap exceeded ({len(remove_candidates)} records, "
                f"{pct:.0f}% of current; abs>{max_removals or 'n/a'} pct>{max_removal_percent}); "
                "removals withheld")
            remove_candidates = []

    plan.add = add
    plan.remove = remove_candidates
    return plan


def execute_former_plan(plan, client, ownership, apply_changes: bool, source: str = "elite-sync") -> dict:
    """Apply a FormerPlan against the SOCRadar client, updating the ownership
    ledger only on readback-confirmed mutations. Pure w.r.t. its injected
    `client` and `ownership` (both may be fakes), so the apply/plan-only/readback
    logic is unit-testable without Azure.

    Returns a dict:
      applied           — True if mutations were attempted (apply mode, not blocked)
      added / removed   — readback-CONFIRMED counts (may be < planned)
      add_planned / remove_planned — what the plan asked for (mismatch = API/actor issue)
    """
    result = {
        "applied": False,
        "added": 0, "removed": 0,
        "add_planned": len(plan.add), "remove_planned": len(plan.remove),
    }
    if plan.blocked or not apply_changes:
        return result

    if plan.add:
        client.add(plan.add, source=source)
        # The add is committed once that call returns. If the readback then
        # fails we cannot tell which entries landed, and both ways of guessing
        # cost something real: claiming them all risks retiring an entry the
        # customer added themselves, claiming none leaves ours on the list with
        # nobody able to remove them. So record the uncertainty by name and stop
        # here rather than resolving it silently — an unowned entry used to be
        # permanent and invisible.
        try:
            after_add = client.get_list()
        except Exception as e:
            result["unconfirmed_adds"] = len(plan.add)
            result["unconfirmed_reason"] = f"add readback failed: {str(e)[:200]}"
            result["applied"] = True
            return result
        confirmed = [e for e in plan.add if e in after_add]
        ownership.mark_owned(confirmed)
        result["added"] = len(confirmed)

    if plan.remove:
        client.remove(plan.remove)
        try:
            after_remove = client.get_list()
        except Exception as e:
            # A removal we cannot confirm is the safer half of the same problem:
            # nothing extra was published, but the tombstone is missing, so the
            # next run re-attempts the removal. Say so instead of reporting zero.
            result["unconfirmed_removes"] = len(plan.remove)
            result["unconfirmed_reason"] = f"remove readback failed: {str(e)[:200]}"
            result["applied"] = True
            return result
        confirmed = [e for e in plan.remove if e not in after_remove]
        ownership.mark_tombstone(confirmed)
        result["removed"] = len(confirmed)

    result["applied"] = True
    return result
