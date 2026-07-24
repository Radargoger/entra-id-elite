# State restore runbook

State lives in four tables: `EntraIDState` (checkpoint + guard baseline),
`FormerManual`, `FormerOwnership` (ledger), `FormerLock`.

The engine is designed so that LOSING state is safe: an empty ownership
ledger is a bootstrap run — removals are forced to zero, external records
are never touched, and adds re-confirm through readback. That gives two
restore strategies; prefer the first.

## Strategy 1 — safe reset (default)

Delete the state tables (or the whole rows) and let the next run
re-bootstrap:

```bash
az storage table delete --account-name <sa> --name FormerOwnership --auth-mode login
az storage table delete --account-name <sa> --name FormerLock --auth-mode login
# EntraIDState / FormerManual: delete only if suspected corrupt.
```

Effects, all fail-safe:
- ownership empty -> bootstrap -> **no removals** until adds re-confirm;
- guard baseline empty -> re-adopts current tenant counts on the next run;
- manual entries lost -> re-add via `POST /api/former/manual`.

Run one plan-only cycle (`FORMER_APPLY_CHANGES=false`) and check
`GET /api/former/preview` before re-enabling apply.

## Strategy 2 — restore from backup

Re-insert the rows from a `backup-state.sh` JSON dump:

```bash
python3 - <<'EOF'
# for each item in <backup>/FormerOwnership.json: az storage entity insert
# (PartitionKey/RowKey/state fields). Left as an explicit operator step —
# restoring a stale ledger is a decision, not an automation.
EOF
```

A restored (possibly stale) ledger may claim ownership of records the
engine no longer manages. After ANY restore: one plan-only cycle +
preview review before apply. Never restore a backup older than the last
apply-mode run without reviewing `withheld_removals` in the preview.

## Drill log

- 2026-07-25: backup-state.sh executed against the live E2E rig
  (elitee2e0725sa) via the account-key fallback path. EntraIDState dumped
  with real guard/checkpoint data; FormerManual/FormerOwnership dumped as
  empty lists (correct — canary was cleaned, plan-only never populates the
  ledger); FormerLock honestly reported FAILED (table not yet created on
  that rig — the lock code postdates its deployment) with no empty file
  left behind. Safe-reset semantics verified by the bootstrap test suite
  (removals=0 on empty ledger).
