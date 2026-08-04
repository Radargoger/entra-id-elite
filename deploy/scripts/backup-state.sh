#!/bin/sh
# Backup the former-sync state tables to timestamped JSON files.
# Usage: sh backup-state.sh <storage-account> [out-dir]
# Auth: tries AAD (Storage Table Data Reader) first, falls back to the
# account key (requires listKeys permission). A failed table leaves no
# empty file behind — absence of a file means NOT backed up.
set -e
SA="$1"
OUT="${2:-./state-backup-$(date -u +%Y%m%dT%H%M%SZ)}"
[ -z "$SA" ] && { echo "usage: sh backup-state.sh <storage-account> [out-dir]"; exit 1; }
mkdir -p "$OUT"

# A row cap that is reached is a partial backup, and a partial backup that says
# nothing looks exactly like a complete one. Raise the cap with BACKUP_LIMIT and
# say so out loud whenever a table comes back at the limit.
LIMIT="${BACKUP_LIMIT:-5000}"

warn_if_truncated() {
  # `az storage entity query` answers with {"items": [...], "nextMarker": ...},
  # so counting the top level always returned 2 and this check never fired.
  # nextMarker is the authoritative signal: the service sets it when it has
  # more rows to give.
  rows=$(python3 -c "
import json,sys
d=json.load(open(sys.argv[1]))
items=d.get('items', d) if isinstance(d,dict) else d
print(len(items), 1 if (isinstance(d,dict) and d.get('nextMarker')) else 0)
" "$OUT/$1.json" 2>/dev/null || echo "0 0")
  more=${rows#* }; rows=${rows%% *}
  if [ "$rows" -ge "$LIMIT" ] || [ "$more" = "1" ]; then
    echo "  WARNING: $1 returned $rows rows = the limit. This backup is INCOMPLETE."
    echo "           Re-run with a higher cap: BACKUP_LIMIT=$((LIMIT * 4)) sh backup-state.sh $SA"
    TRUNCATED="${TRUNCATED}$1 "
  fi
}

TRUNCATED=""
KEY=""
# LeakActionLedger belongs here: apply mode depends on it to tell a repeat from
# a first-time action. FormerLock is deliberately absent -- it is a short-lived
# lease the app recreates, and a stale copy would be worse than none.
for T in EntraIDState FormerManual FormerOwnership LeakActionLedger; do
  echo "backing up $T ..."
  if az storage entity query --account-name "$SA" --table-name "$T" \
       --auth-mode login --num-results "$LIMIT" -o json > "$OUT/$T.json" 2>/dev/null \
     && [ -s "$OUT/$T.json" ]; then
    warn_if_truncated "$T"
    continue
  fi
  # AAD path failed (no Table Data role?) — fall back to the account key.
  # (`|| true`: under set -e a failing key lookup would exit before the
  # cleanup below and leave a 0-byte file looking like a backup.)
  [ -z "$KEY" ] && KEY=$(az storage account keys list --account-name "$SA" \
      --query "[0].value" -o tsv 2>/dev/null || true)
  if [ -z "$KEY" ]; then
    rm -f "$OUT/$T.json"
    echo "  FAILED: $T (no AAD role and no key access) — no file written"
    continue
  fi
  if az storage entity query --account-name "$SA" --table-name "$T" \
       --account-key "$KEY" --num-results "$LIMIT" -o json > "$OUT/$T.json" 2>/dev/null \
     && [ -s "$OUT/$T.json" ]; then
    warn_if_truncated "$T"
    continue
  fi
  rm -f "$OUT/$T.json"
  echo "  FAILED: $T (no access or table missing) — no file written"
done

if [ -n "$TRUNCATED" ]; then
  echo
  echo "INCOMPLETE BACKUP — hit the row cap on: $TRUNCATED"
  echo "Do not treat this directory as a restore point."
  ls -la "$OUT"
  exit 2
fi

echo "done: $OUT"
ls -la "$OUT"
