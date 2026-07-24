"""
Snapshot data-completeness guard for the Former Employee sync (pure logic).

Why this module exists (adversary finding, 2026-07-24): the snapshot gate in
_compute_desired_former_set only checks TOKEN acquisition. A tenant whose Graph
read returns HTTP 200 with silently incomplete data (replication lag, truncated
paging) under-produces its population while snapshot_complete stays True:

  * group tenant under-read  -> sibling_active shrinks -> an owned sibling
    former leaves `desired` -> false removal -> that employee's alarms re-fire.
  * own tenant under-read    -> own_active shrinks -> an active own employee
    stops being subtracted -> could be ADDED to the former list (worse).

The guard compares each tenant's email count against the last healthy baseline.
A suspicious drop (to zero, or by more than drop_percent) marks the snapshot
incomplete, which makes the planner withhold ALL mutation (same fail-closed path
as a token failure).

The baseline is MONOTONIC upward: automatic advancement only ever raises a
tenant's count (max of prior and current). A lower reading — even one under the
trip threshold — never lowers the baseline, so repeated partial reads cannot
ratchet it down and slowly defeat the guard (adversary finding 2026-07-25).

Real shrinkage (layoffs, tenant migration) is therefore the operator's call:
FORMER_GUARD_ACCEPT_DROP=true for one run adopts the current (lower) counts as
the new baseline. Never auto-accepts. The trade-off is explicit: gradual genuine
shrinkage eventually accumulates past drop_percent and trips — that trip is the
prompt for the operator to confirm reality with ACCEPT_DROP.
"""

from dataclasses import dataclass, field


@dataclass
class GuardResult:
    ok: bool = True
    notes: list = field(default_factory=list)
    # Baseline to persist for the next run. On a healthy run it advances to the
    # current counts; on a tripped run it keeps the prior (healthy) counts.
    baseline: dict = field(default_factory=dict)
    # Tenant ids whose reading tripped the guard — multi-company callers block
    # only the companies whose own/group sets intersect these.
    tripped: list = field(default_factory=list)


def evaluate_tenant_counts(
    prior: dict,
    current: dict,
    *,
    drop_percent: int = 50,
    accept_drop: bool = False,
    label: str = "tenant",
) -> GuardResult:
    """Compare per-tenant email counts against the last healthy baseline.

    Args:
      prior:   {tenant_id: count} from the last healthy run (empty on first run).
      current: {tenant_id: count} from this run (only tenants actually read).
      drop_percent: a drop larger than this trips the guard (0 disables the
                    percent check; the zero-read check always applies).
      accept_drop: operator override — adopt current counts as the new baseline
                   without tripping (one-shot, set FORMER_GUARD_ACCEPT_DROP).
      label: "own" | "group", only for note text.

    A tenant missing from `current` is not judged here (the token-level gate
    already handles unread tenants). A tenant with no prior is adopted as-is.
    """
    prior = {str(k): int(v) for k, v in (prior or {}).items()}
    current = {str(k): int(v) for k, v in (current or {}).items()}

    if accept_drop:
        merged = dict(prior)
        merged.update(current)
        return GuardResult(ok=True, baseline=merged,
                           notes=[f"{label} guard: FORMER_GUARD_ACCEPT_DROP set — "
                                  f"adopted current counts as baseline"])

    tripped_ids, tripped_msgs = [], []
    for tenant_id, count in current.items():
        prev = prior.get(tenant_id)
        if prev is None or prev == 0:
            continue  # new tenant or previously-empty: nothing to compare
        if count == 0:
            tripped_ids.append(tenant_id)
            tripped_msgs.append(f"{label} tenant {tenant_id}: {prev} -> 0 emails (zero-read)")
        elif drop_percent > 0 and count < prev * (100 - drop_percent) / 100:
            tripped_ids.append(tenant_id)
            tripped_msgs.append(
                f"{label} tenant {tenant_id}: {prev} -> {count} emails "
                f"(drop > {drop_percent}%)")

    if tripped_ids:
        return GuardResult(
            ok=False,
            baseline=prior,  # keep the healthy baseline for the next comparison
            tripped=tripped_ids,
            notes=[f"{label} guard TRIPPED (suspected partial read; mutation withheld; "
                   f"real shrinkage? set FORMER_GUARD_ACCEPT_DROP=true for one run): "
                   + "; ".join(tripped_msgs)])

    # Monotonic advancement: a healthy run may only RAISE a tenant's baseline.
    # A sub-threshold lower reading is tolerated for this run but not adopted —
    # only ACCEPT_DROP (above) can lower the baseline.
    merged = dict(prior)
    for tenant_id, count in current.items():
        merged[tenant_id] = max(prior.get(tenant_id, 0), count)
    return GuardResult(ok=True, baseline=merged)
