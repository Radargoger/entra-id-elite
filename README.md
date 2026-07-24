# Entra ID Elite

Suppresses false-positive leak alarms for former employees. One deployment
manages every company in a corporate group: each company's former
list receives the active members of the sibling tenants (cross-tenant
suppression) plus its own disabled and deleted members, and never an active
own employee.

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Forcunsami%2Fentra-id-elite%2Fmaster%2Fdeploy%2Fazuredeploy.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2Forcunsami%2Fentra-id-elite%2Fmaster%2Fdeploy%2FcreateUiDefinition.json)

Runs as an Azure Function App. Syncing starts right after deployment;
for a read-only trial turn off Apply changes in the form (plan-only mode).

## Deploy

Portal: use `deploy/azuredeploy.json` with `deploy/createUiDefinition.json`
(custom deployment). The form takes one grid row per company — your own company in the first row, the other group companies below it: company ID,
its own tenant GUIDs, its API key and its actor email. Group tenants are
derived automatically from the other rows.

Creating a new App Registration (the form's default) needs the
Application Administrator role in Entra ID. Without it the deployment
fails — pick "Use an existing App Registration" instead and have an app
owner add the federated credential (the deployment output prints the
exact command).

CLI: see `deploy/README.md`.

## First run

Want to see the plan before it writes? Deploy with Apply changes off. The exact URL is in the
deployment's Outputs tab (previewUrl); take the function key from the
Function App's App keys page:

```
GET https://<functionapp>.azurewebsites.net/api/former/preview?code=<function-key>
```

The response names who would be added or removed per company. Enable
writes by setting `FORMER_APPLY_CHANGES=true`.

## Manual entries

```
POST /api/former/manual?code=<function-key>
{"action": "add", "emails": ["person@company.com"], "company_id": "330"}
```

Manual entries survive reconciles until removed with `action: remove`.

## Safety model

- Plan-only trial available with a single switch (Apply changes off).
- Only records this integration created (readback-confirmed ownership
  ledger) are ever removal candidates; records added in the platform UI
  or by other tools are never touched.
- An incomplete tenant snapshot, the first run, and per-run caps all
  withhold deletions.
- A data-completeness guard blocks mutation when a tenant read shrinks
  suspiciously; real shrinkage is confirmed with
  `FORMER_GUARD_ACCEPT_DROP=true` for one run.
- Timer and manual endpoint are serialized per company with a lease lock.
- Every action lands in the `SOCRadar_EntraID_Audit_CL` Log Analytics
  table with hashed emails.
- A company row without its actor email stays plan-only but is still
  previewed. A row without its API key shows as an error in the preview
  (real mode needs the key even to read the list) until the key or an
  `api_key_setting` reference is added.

## State

Four storage tables: `EntraIDState` (checkpoint + guard baseline),
`FormerManual`, `FormerOwnership` (ledger), `FormerLock`. Losing state is
safe — an empty ledger bootstraps with removals forced to zero. Backup and
restore: `deploy/scripts/`.

## Postman

`postman/` has a collection to check everything from outside Azure: the
app's preview and manual endpoints, plus the platform API directly (so you
can verify the former-employee list independently of the app). Import both
files, fill the environment with your values; keys stay on your machine.

## Tests

```bash
cd FunctionApp
python3 -m pytest tests -q
```
