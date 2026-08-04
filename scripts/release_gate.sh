#!/usr/bin/env bash
# Install the shipped artefacts into a throwaway resource group and check that
# the result is actually usable, then delete it.
#
#   scripts/release_gate.sh
#   scripts/release_gate.sh --keep        # leave the group for inspection
#
# Exit: 0 proven · 1 a check failed or cleanup left something behind · 2 the
# package installs but readiness could not be proven from this account.
#
# WHAT THIS GATE DOES NOT COVER. It is the only check that installs the shipped
# bytes, which makes it easy to read as "the release is fine". It is not:
#   - the default Deploy-button path (this runs the reuse path, not
#     CreateAppRegistration=true)
#   - createUiDefinition.json — the form a customer actually fills in
#   - the real SOCRadar client (runs with FormerClientMode=mock)
#   - any directory mutation (apply is off, responses are logOnly)
#   - the timer path, the idempotency ledger, multi-company isolation
#   - that the bytes published afterwards are the bytes tested here — compare
#     the sha256 by hand after uploading
#
# Not in CI on purpose: it creates real resources and costs real money, and
# this project has a standing rule about leaving test resources running.

set -euo pipefail

KEEP=0
[ "${1:-}" = "--keep" ] && KEEP=1

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMPLATE="$REPO_ROOT/deploy/azuredeploy.json"
STAMP="$(date -u +%m%d%H%M)"
RG="gate-$STAMP"
FIC_NAME="former-elite-$RG-uami"
LOCATION="${LOCATION:-northeurope}"

pass() { printf '  \033[32mOK\033[0m   %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAILED=1; }
step() { printf '\n\033[1m%s\033[0m\n' "$1"; }
# A step that could not be run is not a step that passed. Kept apart from
# FAILED so an unprovable check never reads as a green one.
unproven() { printf '  \033[33m????\033[0m %s\n' "$1"; UNPROVEN=1; }
FAILED=0
UNPROVEN=0
RESULT=0

# The exit code used to be decided before cleanup ran, so a run that printed
# "DELETE IT BY HAND" still exited 0 and read as a clean release. The trap has
# the last word now.
cleanup() {
  local code=$?
  step "Cleaning up"
  # `|| true` throughout: under set -e a failure here would abandon the rest of
  # the cleanup, and the part left undone is the one that bills.
  [ -n "${PARAMS:-}" ] && rm -f "$PARAMS" || true
  rm -f "/tmp/$RG.err" "/tmp/$RG.fic" || true
  if [ "$KEEP" = "1" ]; then
    printf '\n--keep: %s left in place, and %s may still be on the App Registration.\n' "$RG" "$FIC_NAME"
    printf 'Delete both when you are done. The next run sweeps stale gate credentials.\n'
    exit $code
  fi
  if az group show -n "$RG" >/dev/null 2>&1; then
    az group delete -n "$RG" --yes --no-wait -o none 2>/dev/null || true
    # Confirm the delete was accepted rather than assuming it. A group left
    # behind here bills until someone notices.
    sleep 10
    if az group show -n "$RG" --query properties.provisioningState -o tsv 2>/dev/null | grep -q Deleting; then
      pass "$RG is being deleted"
    elif ! az group show -n "$RG" >/dev/null 2>&1; then
      pass "$RG is gone"
    else
      printf '  \033[31mFAIL\033[0m %s\n' "$RG still exists — DELETE IT BY HAND: az group delete -n $RG --yes"
      code=1
    fi
  fi
  # The credential outlives the resource group: it lives on a shared, long-lived
  # App Registration. Removed after the group, never before — a failure here
  # must not be able to strand the thing that costs money. Anything missed is
  # swept by the next run's preflight, which also covers a kill -9.
  if [ "${FIC_ADDED_HERE:-0}" = "1" ]; then
    # No --yes here: this command does not take one, and passing it made every
    # delete fail with "unrecognized arguments". With stderr discarded the run
    # reported "delete it by hand" without ever saying why, so the error is
    # shown now.
    local err
    if err=$(az ad app federated-credential delete --id "${GATE_APP_ID:-}" \
               --federated-credential-id "$FIC_NAME" 2>&1); then
      pass "removed the federated credential this run added"
    else
      printf '  \033[31mFAIL\033[0m %s\n' "could not remove $FIC_NAME: $(printf '%s' "$err" | head -1)"
      printf '         delete it from the App Registration by hand\n'
      code=1
    fi
  fi
  exit $code
}
trap cleanup EXIT

step "Preflight"
command -v az >/dev/null || { echo "az not found"; exit 1; }
SUB=$(az account show --query name -o tsv) || { echo "run: az login"; exit 1; }
pass "subscription: $SUB"

# az account show serves a cached value, so it says nothing about whether the
# subscription can still take writes. A Warned (read-only) subscription fails
# the deployment below, and that failure reads exactly like a broken template
# -- an afternoon was once lost to that misattribution.
SUB_ID=$(az account show --query id -o tsv)
SUB_STATE=$(az rest --method GET \
  --uri "https://management.azure.com/subscriptions/$SUB_ID?api-version=2022-12-01" \
  --query state -o tsv 2>/dev/null || echo "unreadable")
[ "$SUB_STATE" = "Enabled" ] && pass "subscription state: Enabled (read from ARM)" \
  || { fail "subscription state is '$SUB_STATE', not Enabled — a deployment failure here would not be about the code"; exit 1; }

# Set GATE_PACKAGE_URI to test a package that is not published yet. Without it
# the gate installs whatever the template points at, which is the code already
# in customers' hands — useful for checking a template change, useless for
# checking new code. Uploading first and testing afterwards would mean every
# running installation picks up untested code the moment it restarts, because
# the release URL never changes (product-policy §1).
PKG=$(python3 -c "import json;print(json.load(open('$TEMPLATE'))['parameters']['PackageUri']['defaultValue'])")
if [ -n "${GATE_PACKAGE_URI:-}" ]; then
  PKG="$GATE_PACKAGE_URI"
  printf '  \033[33mNOTE\033[0m candidate package, not the published one\n'
fi
CODE=$(curl -sIL -o /dev/null -w '%{http_code}' "$PKG")
[ "$CODE" = "200" ] && pass "package reachable: ${PKG##*/}" \
                    || { fail "package returns HTTP $CODE — upload the asset first"; exit 1; }

: "${GATE_COMPANY_ID:?set GATE_COMPANY_ID}"
: "${GATE_API_KEY:?set GATE_API_KEY (never commit it)}"
: "${GATE_APP_ID:?set GATE_APP_ID (existing multi-tenant App Registration)}"
TENANT=$(az account show --query tenantId -o tsv)

# Sweep credentials left by earlier runs. This is the backstop, not the trap: a
# kill -9 skips every trap, and each orphan points at an identity that no longer
# exists.
STALE=$(az ad app federated-credential list --id "$GATE_APP_ID" \
        --query "[?starts_with(name,'former-elite-gate-')].name" -o tsv 2>/dev/null || echo "")
if [ -n "$STALE" ]; then
  for s in $STALE; do
    if sweep_err=$(az ad app federated-credential delete --id "$GATE_APP_ID" \
                     --federated-credential-id "$s" 2>&1); then
      printf '  \033[33mNOTE\033[0m swept a leftover credential: %s\n' "$s"
    else
      fail "leftover credential $s could not be removed ($(printf '%s' "$sweep_err" | head -1)) — do it by hand"
    fi
  done
else
  pass "no leftover gate credentials on the App Registration"
fi

step "Deploying $RG"
az group create -n "$RG" -l "$LOCATION" -o none
# The parameter file holds a live customer API key. Written under the default
# umask into a predictable path it was world-readable, and the delete below is
# skipped on the failure path, so a failed gate run left the key in /tmp for
# good. Create it private, and let the exit trap remove it either way.
PARAMS="$(mktemp "${TMPDIR:-/tmp}/gate-params.XXXXXX")"
chmod 600 "$PARAMS"
cat > "$PARAMS" <<JSON
{
  "FormerCompanies": { "value": { "rows": [
    { "companyId": "$GATE_COMPANY_ID", "tenantIds": "$TENANT",
      "apiKey": "$GATE_API_KEY", "actorEmail": "${GATE_ACTOR_EMAIL:-gate@example.com}" }
  ] } },
  "EntraIdClientId": { "value": "$GATE_APP_ID" },
  "EnableLeakMonitoring": { "value": true },
  "LeakResponse": { "value": "logOnly" },
  "FormerClientMode": { "value": "mock" },
  "FormerApplyChanges": { "value": false },
  "PackageUri": { "value": "$PKG" }
}
JSON
# logOnly and mock on purpose: this gate proves the install works, it is not a
# licence to mutate somebody's directory.

: > "/tmp/$RG.err"; chmod 600 "/tmp/$RG.err"
if az deployment group create -g "$RG" -n gate --template-file "$TEMPLATE" \
     --parameters "@$PARAMS" -o none 2>"/tmp/$RG.err"; then
  pass "deployment succeeded"
else
  fail "deployment failed"
  head -20 "/tmp/$RG.err"
  exit 1
fi

step "Checking what the deployment reported"
OUTPUTS=$(az deployment group show -g "$RG" -n gate --query properties.outputs -o json)
FIC_NOTE=$(python3 -c "import json,sys;print((json.loads(sys.argv[1]) or {}).get('ficNote',{}).get('value',''))" "$OUTPUTS")
FIC_CMD=$(python3 -c "import json,sys;print((json.loads(sys.argv[1]) or {}).get('ficManualCommand',{}).get('value',''))" "$OUTPUTS")
FIC_PENDING=0
case "$FIC_NOTE" in
  "") fail "no ficNote in the outputs" ;;
  *"ACTION REQUIRED"*|*"CHECK THIS"*)
      # Expected on the reuse path: the deployment script runs as the managed
      # identity this deployment just created, and that identity holds no Entra
      # permission, so it can never write to an App Registration it does not
      # own. Failing the release on it made this gate structurally unable to go
      # green, and a check that is always red teaches people to ignore red.
      printf '  \033[33mNOTE\033[0m credential not added by the deployment (expected on the reuse path)\n'
      FIC_PENDING=1 ;;
  *)  pass "ficNote: ${FIC_NOTE:0:60}..." ;;
esac

APP=$(az functionapp list -g "$RG" --query "[0].name" -o tsv)
[ -n "$APP" ] && pass "function app: $APP" || { fail "no function app"; exit 1; }

step "Waiting for the host to index the functions"
KEY=$(az functionapp keys list -g "$RG" -n "$APP" --query masterKey -o tsv)
COUNT=0
for _ in $(seq 1 20); do
  COUNT=$(curl -s -H "x-functions-key: $KEY" "https://$APP.azurewebsites.net/admin/functions" \
          | python3 -c "import json,sys;print(len(json.load(sys.stdin)))" 2>/dev/null || echo 0)
  [ "$COUNT" -ge 6 ] && break
  sleep 15
done
# A package the Linux worker cannot read indexes zero functions while the host
# still reports Running, so the count is the only honest signal here.
[ "$COUNT" -ge 6 ] && pass "$COUNT functions indexed" \
                   || fail "only $COUNT functions indexed — check the package entry permissions"

# Reads former/preview and says which state it is in. An HTTP 200 carrying a
# per-company error used to count as an answer, so an app that could do nothing
# at all read as ready.
former_state() {
  curl -s -H "x-functions-key: $KEY" "https://$APP.azurewebsites.net/api/former/preview" 2>/dev/null \
  | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    print("unreadable: not json"); raise SystemExit
cs = d.get("companies") or []
if not cs:
    print("unreadable: no companies in the response"); raise SystemExit
errs = [c.get("error") for c in cs if c.get("error")]
if errs:
    print("incomplete: " + str(errs[0])[:80]); raise SystemExit
print("healthy" if all(c.get("snapshot_complete") for c in cs)
      else "incomplete: snapshot_complete is false")
' 2>/dev/null || echo "unreadable: could not be parsed"
}

# Measure twice. Before the credential exists, the expected state is the broken
# one every reuse customer lands in — asserting it is the only coverage that
# world gets, and skipping straight to the fix would delete it.
if [ "$FIC_PENDING" = "1" ]; then
  step "Before the credential: the state a reuse customer actually lands in"
  STATE=$(former_state)
  case "$STATE" in
    incomplete*) pass "reports itself incomplete, as the template's note says it should" ;;
    healthy)     fail "claims to be healthy without a federated credential — it cannot be" ;;
    *)           fail "could not read former/preview: $STATE" ;;
  esac

  step "Adding the federated credential the way a customer is told to"
  # Built here rather than eval'd from the deployment output: that string
  # arrives over the network, and running it would execute whatever it contains
  # under this account. Build it locally, then check the template's version
  # agrees with it.
  UAMI=$(az identity list -g "$RG" --query "[0].principalId" -o tsv 2>/dev/null || echo "")
  if [ -z "$UAMI" ]; then
    fail "no managed identity in $RG — cannot build the credential"
  elif [ -z "$FIC_CMD" ]; then
    fail "ficNote asks for a credential but ficManualCommand is empty — a customer would be stuck here"
  else
    case "$FIC_CMD" in
      *"$GATE_APP_ID"*"$UAMI"*) pass "the printed command names this app and this identity" ;;
      *) fail "ficManualCommand does not match this deployment — a customer would add the wrong credential" ;;
    esac
    : > "/tmp/$RG.fic"; chmod 600 "/tmp/$RG.fic"
    if az ad app federated-credential create --id "$GATE_APP_ID" --parameters "{
         \"name\": \"$FIC_NAME\",
         \"issuer\": \"https://login.microsoftonline.com/$TENANT/v2.0\",
         \"subject\": \"$UAMI\",
         \"audiences\": [\"api://AzureADTokenExchange\"]
       }" >"/tmp/$RG.fic" 2>&1; then
      FIC_ADDED_HERE=1
      pass "credential added"
    else
      # Being unable to add it does not make the release bad, but it does mean
      # the checks below cannot speak. Say which of the two happened.
      unproven "could not add it from this account — needs an owner of the App Registration"
      head -3 "/tmp/$RG.fic"
    fi
  fi
fi

step "Asking the app whether it can do its job"
if [ "$UNPROVEN" = "1" ]; then
  unproven "readiness checks skipped — without the credential they measure the install, not the release"
else
  # Poll rather than sleep once: the token endpoint does not serve a new
  # credential immediately, and a propagation delay looks exactly like a broken
  # release. Same discipline as the function count above.
  STATE=""
  for _ in $(seq 1 8); do
    STATE=$(former_state)
    [ "$STATE" = "healthy" ] && break
    sleep 15
  done
  [ "$STATE" = "healthy" ] && pass "former/preview reports a complete snapshot" \
                           || fail "former/preview never became healthy: $STATE"

  # Polled for the same reason former/preview is: these are two different token
  # paths, and the leak one has been seen to lag behind a credential the former
  # one already accepts. Asking once turned that lag into a release failure.
  REACHABLE=1
  for _ in $(seq 1 8); do
    PREVIEW=$(curl -s -H "x-functions-key: $KEY" \
      "https://$APP.azurewebsites.net/api/leak/preview?company_id=$GATE_COMPANY_ID" || echo '{}')
    if printf '%s' "$PREVIEW" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(1)
sys.exit(0 if any(c.get("tenants_reachable") for c in (d.get("companies") or [])) else 1)
'; then REACHABLE=0; break; fi
    sleep 15
  done
  [ "$REACHABLE" = "0" ] && pass "leak/preview reports a reachable tenant" \
    || fail "leak/preview: no tenant reachable after 2 minutes (the app cannot get a Graph token)"
fi

step "Result"
if [ "$FAILED" != "0" ]; then
  printf '  \033[31mDo not announce this release.\033[0m\n'
  RESULT=1
elif [ "$UNPROVEN" != "0" ]; then
  # Distinct from both other outcomes on purpose. "Could not be checked"
  # reported as a pass is how a release goes out unverified; reported as a
  # failure is how people learn to ignore the gate. The sentence still has to
  # decide something — a neutral one nudges towards shipping.
  printf '  \033[33mNot proven by this run — do not announce it on the strength of this.\033[0m\n'
  printf '  The package deploys and the host loads it. Readiness was not established.\n'
  printf '  Re-run as an owner of the App Registration, or add the credential by hand first.\n'
  RESULT=2
else
  printf '  \033[32mThe shipped artefacts install and work. Safe to announce.\033[0m\n'
  printf '  Read the coverage note at the top of this file before reading that as "the release is fine".\n'
fi
exit "$RESULT"
