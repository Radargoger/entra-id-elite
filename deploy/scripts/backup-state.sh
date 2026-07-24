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

KEY=""
for T in EntraIDState FormerManual FormerOwnership FormerLock; do
  echo "backing up $T ..."
  if az storage entity query --account-name "$SA" --table-name "$T" \
       --auth-mode login --num-results 1000 -o json > "$OUT/$T.json" 2>/dev/null \
     && [ -s "$OUT/$T.json" ]; then
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
       --account-key "$KEY" --num-results 1000 -o json > "$OUT/$T.json" 2>/dev/null \
     && [ -s "$OUT/$T.json" ]; then
    continue
  fi
  rm -f "$OUT/$T.json"
  echo "  FAILED: $T (no access or table missing) — no file written"
done

echo "done: $OUT"
ls -la "$OUT"
