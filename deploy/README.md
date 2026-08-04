# Deploy — Entra ID Elite

One deployment manages every company in a corporate group. Each
grid row is one company: its ID, its own tenant GUIDs, its API key and its
actor email. Group tenants are derived automatically from the other rows —
never entered.

Syncing starts right after deployment; set `FormerApplyChanges=false`
for a plan-only trial. Check `GET /api/former/preview?code=<function-key>` first —
it shows exactly who the next run would add or remove.

Leaked-credential monitoring is a second, optional capability
(`EnableLeakMonitoring`, off by default). Each company is searched only in its
own tenants, `LeakResponse` defaults to `logOnly`, and `LeakMaxActionsPerRun`
caps account changes **per company per source** — a run's real maximum is that
number × companies × enabled sources, not the number by itself. Write
permissions are requested only for the responses listed in
`LeakResponseActions`.

## Files

| File | What |
|---|---|
| `main.bicep` | source template (build with `az bicep build`) |
| `azuredeploy.json` | compiled template (portal / Deploy button) |
| `createUiDefinition.json` | portal form: environment dropdown + company grid |
| `bicepconfig.json` | Microsoft Graph bicep extension config |

## Portal form to engine mapping

The company grid emits `[{companyId, tenantIds, apiKey, actorEmail}]`; the
template passes it through as the `FORMER_COMPANY_MAP` app setting and the
engine parses both these names and the snake_case originals. A row without an
**actor email** stays plan-only but is still previewed. A row without its **API
key** is different: real mode needs the key even to read the list, so that
company shows as an error in the preview until the key or an `api_key_setting`
reference is added.

## CLI deploy

`FormerCompanies` is an object holding a `rows` array — the template reads
`FormerCompanies.rows`, so a bare array is rejected. Put it in a file rather
than on the command line: the rows carry API keys, and a shell history is a
poor place for those.

```bash
cat > params.json <<'JSON'
{
  "FormerCompanies": { "value": { "rows": [
    { "companyId": "1234567", "tenantIds": "<guid>",
      "apiKey": "<key>", "actorEmail": "user@company.com" }
  ] } },
  "Environment": { "value": "platform" },
  "EntraIdClientId": { "value": "<existing-app-id>" }
}
JSON
chmod 600 params.json
az deployment group create -g <rg> \
  --template-file azuredeploy.json --parameters @params.json
rm -f params.json
```

Leave `EntraIdClientId` empty to create a new App Registration with
User.Read.All — the FIC to the managed identity is created automatically on
this path.

When reusing an existing App Registration, plan on adding the FIC yourself.
The script that would add it runs as the managed identity this deployment
just created, and that identity holds no Entra permission at all, so it
cannot write to an App Registration it does not own. Your own rights do not
change that: a Global Administrator gets the same result. The deployment
still reports success and prints the exact `az ad app federated-credential
create` command — run it as an owner of the app. Until it exists the app
gets no Graph token and looks nobody up. Confirm with `GET
/api/former/preview`. Consent the multi-tenant app once in every sibling
tenant.

`PackageUri` points at the FunctionApp zip release; empty deploys the
infrastructure only.

## Key Vault keys

Deploy a row with an empty key, then set an app setting the map can
reference: change the row to `"api_key_setting": "FORMER_KEY_1234567"` and add
`FORMER_KEY_1234567` as a Key Vault reference app setting. Until the reference
is in place that company appears as an error in the preview — real mode
needs the key even to read the list.
