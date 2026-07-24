# Deploy — Entra ID Elite

One deployment manages every company in a corporate group. Each
grid row is one company: its ID, its own tenant GUIDs, its API key and its
actor email. Group tenants are derived automatically from the other rows —
never entered.

Syncing starts right after deployment; set `FormerApplyChanges=false`
for a plan-only trial. Check `GET /api/former/preview?code=<function-key>` first —
it shows exactly who the next run would add or remove.

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
engine parses both these names and the snake_case originals. A row without
an API key or actor email stays plan-only but is still previewed.

## CLI deploy

```bash
az deployment group create -g <rg> \
  --template-file azuredeploy.json \
  --parameters FormerCompanies='[{"companyId":"330","tenantIds":"<guid>","apiKey":"<key>","actorEmail":"user@company.com"}]' \
               Environment=platform EntraIdClientId=<existing-app-id>
```

Leave `EntraIdClientId` empty to create a new App Registration with
User.Read.All + Directory.Read.All — the FIC to the managed identity is
created automatically on this path. When reusing an existing App
Registration the deployment script can only add the FIC if the deployer
identity may write to that app; otherwise the deployment still succeeds
and the script output prints the exact `az ad app federated-credential
create` command to run as an app owner. Consent the multi-tenant app once
in every sibling tenant.

`PackageUri` points at the FunctionApp zip release; empty deploys the
infrastructure only.

## Key Vault keys

Deploy a row with an empty key, then set an app setting the map can
reference: change the row to `"api_key_setting": "FORMER_KEY_330"` and add
`FORMER_KEY_330` as a Key Vault reference app setting. Until the reference
is in place that company appears as an error in the preview — real mode
needs the key even to read the list.
