# Entra ID Elite

Two capabilities over one Entra ID connection, both across every company in a
corporate group.

**Former employees.** Suppresses false-positive leak alarms. Each company's
former list receives the active members of the sibling tenants (cross-tenant
suppression) plus its own disabled and deleted members, and never an active own
employee.

**Leaked credentials** (optional). Pulls botnet, PII exposure and VIP findings
for each company and matches them against that company's own directory. A match
is recorded, and if you ask for it, the account is signed out, forced to change
its password, disabled, or has its MFA registration reset. Off by default; a
company is only ever searched in its own tenants.

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FRadargoger%2Fentra-id-elite%2Fmain%2Fdeploy%2Fazuredeploy.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2FRadargoger%2Fentra-id-elite%2Fmain%2Fdeploy%2FcreateUiDefinition.json)

Runs as an Azure Function App. Syncing starts right after deployment;
for a read-only trial turn off Apply changes in the form (plan-only mode). That
covers the scheduled sync; `POST /api/former/manual` is a deliberate operator
override and writes whatever it is given, in either mode.

Leave **Client mode** on *Real*. *Mock* is a development option: it writes the
former list to a local storage table and never contacts the platform, while the
run still reports what it "added". It is not the trial — the trial switch is
Apply changes.

## Deploy

Portal: use `deploy/azuredeploy.json` with `deploy/createUiDefinition.json`
(custom deployment). The form takes one grid row per company — your own company in the first row, the other group companies below it: company ID,
its own tenant GUIDs, its API key and its actor email. Group tenants are
derived automatically from the other rows.

A tenant that belongs to the group but has no company of its own on the
platform, such as a holding tenant, goes in **Other group tenants** instead.
Its active members are suppressed for every company in the grid; it never
receives a former list itself. The app has to be consented in each tenant
listed there. Without that the snapshot is incomplete, and an incomplete
snapshot stops **everything** for that company — no removals and no additions
either, so nobody gets suppressed until the consent is in place.

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
- The scheduled reconcile only ever considers records this integration
  created (readback-confirmed ownership ledger) for removal; records added
  in the platform UI or by other tools are never touched by it. The manual
  endpoint is the exception and removes exactly the addresses you name,
  ownership or not.
- The first run and the per-run caps withhold deletions. An incomplete tenant
  snapshot is stricter than both: it withholds every change for that company,
  additions included.
- A data-completeness guard blocks mutation when a tenant read shrinks
  suspiciously. To confirm real shrinkage, set `FORMER_GUARD_ACCEPT_DROP=true`,
  let one run finish, then **remove the setting again** — nothing clears it for
  you, and while it is set that guard never trips.
- Timer and manual endpoint are serialized per company with a lease lock.
- Every action lands in the `SOCRadar_EntraID_Audit_CL` Log Analytics
  table with hashed emails.
- A company row without its actor email stays plan-only but is still
  previewed. A row without its API key shows as an error in the preview
  (real mode needs the key even to read the list) until the key or an
  `api_key_setting` reference is added.

## Leaked credentials

Turn it on in the Leaked credentials step. The first check runs as soon as the
deployment finishes, then on the schedule you picked. Findings land in
`SOCRadar_Botnet_CL`, `SOCRadar_PII_CL` and `SOCRadar_VIP_CL`, one row per
finding with the `company_id` it belongs to; run summaries go to
`SOCRadar_ImportAudit_CL`.

Fill in **Your own email domains** to keep the search inside them. An address a
feed returns from outside those domains is dropped inside the app and is never
sent to Microsoft. Leave it empty and every address the feed returns is looked
up.

Not every finding carries an address. VIP findings in particular often name a
person rather than an address, and there is nothing in them to match against a
directory. Those rows still land in the table, with `entra_status` set to
`skipped_no_address`, and `no_address_count` in the run summary says how many
there were. They are findings you may still want to read; they are just not
findings the app can tie to an account. The app does not guess — it will not
send a person's name to Microsoft as though it were an address.

Two more ways a record can leave without being matched, and they mean opposite
things. `lookup_disabled_count` is your own choice — directory matching is
switched off, so nothing was missed. `no_token_count` is not: no tenant produced
a Graph token, so those findings were never checked against anybody. A run that
reports the second one holds its window and reads it again rather than retiring
findings nobody looked at.

A lookup can also fail outright, with a 403 or a server error. That is not the
same as coming back empty, so it has its own counter, `lookup_failed_count`,
and the window is held and read again rather than written off.

Every record a **finished** run handled falls into exactly one of `found_count`,
`not_found_count`, `domain_filtered`, `no_address_count`,
`lookup_disabled_count`, `no_token_count` and `lookup_failed_count`, and those
seven add up to `total_records`. A run that stopped early reports `truncated`
and legitimately accounts for fewer records than it pulled — the rest are read
again next time. On a finished, error-free run the parts have to close; if they
do not, the summary is hiding something.

Safety works the same way as the former sync:

- **Log only is the default.** Nothing in the directory changes, matches are
  just recorded. Responding is a separate choice.
- **Each company is searched only in its own tenants.** A finding for one
  company can never trigger a change in another company's directory.
- **A ceiling of 50 account changes** (the default) applies **per company per
  source**, so a single scheduled run can change up to 50 × companies × enabled
  sources accounts — with three companies and two sources that is 300, not 50.
  Size it against that number, not against one run. Matches keep being recorded
  once the ceiling is reached. A manual `/api/leak/probe` call acts once, on one
  address, and is not counted against it.
- **Only the responses you pick are requested as permissions.** Leave an action
  unselected and its write permission is never asked for and never runs. Adding
  people to a group is not in that list: it is not a checkbox but a consequence
  of filling in **Security group object ID**. Fill it in and group write
  permission is requested; leave it empty and it is not.
- A failed feed read or a failed lookup is reported as an error, not as a clean
  run with no findings, and the window is read again rather than skipped. After
  a few failed attempts the run moves on and records that it did.

### Undoing a response

| Response | How to undo |
|---|---|
| Sign the user out everywhere | Nothing to undo; the user signs in again |
| Require a password change | Clear it in Entra ID: user's profile, reset the flag |
| Disable the account | Re-enable it in Entra ID: the user's profile, **Account enabled** |
| Reset MFA registration | **Cannot be undone.** The user must register their methods again |
| Confirm compromised | Dismiss the risk in Entra ID Protection: **Risky users**, select the user, **Dismiss user risk** |
| Add to a security group | Remove the member in Entra ID: the group's **Members** list. Whatever that group grants or restricts applies until you do |
| Remove from a security group | Add the member back in the same place |
| Re-enable the account | Disable it again in the user's profile, **Account enabled** |

The last three are not checkboxes on the form. Adding people to a group is
turned on by filling in **Security group object ID** and nothing else, so a
deployment that responds at all and names a group is also changing group
membership — leave the field empty if that is not what you want. Removing from
the group and re-enabling accounts stay off unless `ENABLE_REMOVE_FROM_GROUP`
or `ENABLE_ENABLE_ACCOUNT` is set in the app's settings.

Confirming a user as compromised needs Entra ID P2. Without that licence
the response is attempted and recorded as `confirm_risky_failed`. That finding
is **not** processed again on a later run — the window moves on regardless. So
grant the licence, or the permission, before turning the response on rather
than after.

Because MFA reset cannot be undone, start with Log only and confirm the matches
look right before turning responses on.

Two actions are deliberately not offered: password validation (ROPC) needs a
public-client setting this template does not write, and Microsoft Sentinel
incident creation needs workspace identifiers it does not pass.

## State

Four storage tables: `EntraIDState` (checkpoint + guard baseline),
`FormerManual`, `FormerOwnership` (ledger), `LeakActionLedger` (which responses
have already been applied, so a re-read window does not repeat them). A fifth,
`FormerLock`, is created on demand as a short-lived lease. Losing state is
safe — an empty ledger bootstraps with removals forced to zero. Backup and
restore: `deploy/scripts/`.

`LeakActionLedger` rows are dropped once no re-read can reach their window
again: each run clears a slice older than 90 days
(`LEAK_LEDGER_RETENTION_DAYS`, floored at 30). Without that the table would
keep a row per person per response for the life of the deployment.

## Is it working?

Four ways to check, from quickest to most independent.

**1. Ask the app.** `GET /api/former/preview?code=<function-key>` returns, per
company, whether every tenant was read (`snapshot_complete`) and who would be
added or removed. A `false` there is the signal that something is missing, most
often the federated credential.

`GET /api/leak/preview?code=<function-key>` adds which tenants leak monitoring
can reach and which responses are armed. It reports no reachable tenant while
leak monitoring is off, so read it as a leak-side check only, not as a verdict
on the install.

**2. Ask about one person.** `POST /api/leak/probe` with an address and a
company ID says where that person was found. It changes nothing unless you ask
it to. It covers only the two reversible responses — sign-out and password
change. Disabling an account, resetting MFA and confirming compromise are left
to the scheduled run, so the probe neither shows nor performs them: an empty
`would_run` here does not mean the schedule would do nothing.

**3. Read the log.** In the workspace this deployment created:

```kusto
// Every run, newest first: how much was pulled, matched, acted on
SOCRadar_ImportAudit_CL
| order by TimeGenerated desc
| project TimeGenerated, company_id, source, total_records, found_count,
          not_found_count, no_address_count, lookup_disabled_count,
          no_token_count, lookup_failed_count, domain_filtered, actions_taken,
          error_count, capped, truncated
| take 20
```

```kusto
// Does the summary account for every record it handled?
// Finished runs only: a truncated or failed run legitimately accounts for less.
SOCRadar_ImportAudit_CL
| where TimeGenerated > ago(7d) and not(truncated) and error_count == 0
| extend accounted = found_count + not_found_count + domain_filtered
                   + no_address_count + lookup_disabled_count + no_token_count
                   + lookup_failed_count
| where accounted != total_records
| project TimeGenerated, company_id, source, total_records, accounted
```

```kusto
// Anything that went wrong in the last day
SOCRadar_ImportAudit_CL
| where TimeGenerated > ago(1d)
        and (error_count > 0 or truncated or capped or lookup_failed_count > 0)
| project TimeGenerated, company_id, source, error_count, lookup_failed_count,
          truncated, capped
```

```kusto
// Leaked credentials matched to a real account
union SOCRadar_Botnet_CL, SOCRadar_PII_CL, SOCRadar_VIP_CL
| where entra_status == "found"
| project TimeGenerated, company_id, email, severity, actions_taken
```

```kusto
// Former-employee reconciliation (emails are hashed here by design)
SOCRadar_EntraID_Audit_CL
| where event_type == "former_reconcile_summary"
| project TimeGenerated, company_id, added, removed, blocked, block_reason
```

A run that found nothing looks the same as a healthy one — except that on a
healthy run `error_count`, `lookup_failed_count` and `truncated` are all zero.
If any of them is set, the window was not fully read and will be tried again.
`capped` also holds the window now: the run reached its ceiling, matches were
recorded, and the re-read gives the remaining accounts their turn — the ledger
skips everyone already acted on, so nothing is done twice. A feed that outruns
the ceiling every single run is bounded the same way as any other hold: after a
few attempts the window is abandoned with an `import_window_abandoned` event.

**4. Check it against Entra ID's own record.** Every matched row carries
`entra_user_id`, the account's object ID, which is what Microsoft Entra ID's
audit log records a change against. So the app's account of what it did can be
lined up with the directory's own account of what happened, rather than taken on
trust:

```kusto
union SOCRadar_Botnet_CL, SOCRadar_PII_CL, SOCRadar_VIP_CL
| where array_length(actions_taken) > 0
| project TimeGenerated, company_id, entra_tenant_id, entra_user_id, actions_taken
```

Take an `entra_user_id` from that result to **Entra ID > Monitoring > Audit
logs**, filter by target, and the two records should agree.

The app's own traces live in the same workspace, so one query can span both:

```kusto
union AppTraces, SOCRadar_ImportAudit_CL
| where TimeGenerated > ago(1h)
| order by TimeGenerated desc
```

## Who needs which permission

| Action | Needed | If you do not have it |
|---|---|---|
| Deploy the template | Contributor on the subscription or resource group | Ask your Azure admin |
| Create a new App Registration (form default) | Application Administrator role in Entra ID | Pick "Use an existing App Registration" instead, or ask your Entra admin to run the deployment |
| Grant admin consent automatically (optional checkbox) | Global Administrator or Privileged Role Administrator | Leave it off; any admin can grant consent later under App registrations > API permissions |
| Link the identity on the existing-app path | Owner of that App Registration | Send the one-line command from the deployment Outputs to the app owner |
| Respond to leaked credentials | Consent in every tenant you listed, granted by that tenant's admin | Stay on Log only; matches are still recorded |

Day-to-day operation needs none of these: the app runs by itself.

Reading is `User.Read.All`, which also covers the deleted-user list. Write permissions are
requested only for the responses you turn on, so a tenant admin is never asked
to consent to something the deployment will not do. The automatic-consent
checkbox covers the read permissions only; permission to change accounts is
always granted by a person on the consent screen. Turning a response off later
stops the app using it, but does not revoke a consent already given — remove it
under App registrations > API permissions.

## Keys and secrets

The HTTP endpoints are protected by the Function App's own key. Anyone holding
it can read `/api/former/preview` and `/api/leak/probe`, which return real email
addresses for every company in the deployment. Treat it like a password: if it
ends up in a ticket, a screenshot or a shared tool, rotate it under
**Function App → App keys → Renew**, then update whatever was using it.

One setting is deliberately left off and should stay that way:

- `ENABLE_ROPC` — attempts a real sign-in with the leaked password, which shows
  up in your tenant's sign-in logs and can trigger lockouts.

The leaked credential is recorded exactly as SOCRadar delivered it. Whether it
arrives masked or in the clear is a per-company setting in the SOCRadar
platform, so a company that does not want cleartext leaving SOCRadar never has
it sent here. The `password_masked` column is derived locally either way, so a
dashboard can show something safe without reading the credential itself.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Deployment fails with Authorization_RequestDenied | "Create new automatically" chosen without the Application Administrator role | Redeploy with "Use an existing App Registration", or have an Entra admin deploy |
| Preview shows a company error mentioning token or tenant | Identity link (FIC) or tenant consent missing | Run the command from the deployment Outputs; consent the app in that tenant |
| Preview returns 401 | Wrong or missing function key | Copy a key from the Function App's App keys page |
| A company row shows an API-key error | Key empty or wrong for that company | Add the correct key (or an api_key_setting reference) |
| Manual add returns 409 | A sync is writing that company right now | Retry in a minute |
| Adds report success but the platform list stays empty | Client mode is Mock, or the actor email does not belong to that company | Set Client mode to Real; verify the actor email; if both are right, contact support |
| Nobody is suppressed and `blocked` says `incomplete_snapshot` | A listed tenant has not consented to the app | Consent it there — until then that company gets no additions either |

## Postman

`postman/` has a collection to check everything from outside Azure: the app's
preview, manual, leak preview and probe endpoints, plus the platform API
directly (so you can verify the former-employee list independently of the app).
Import both files, fill the environment with your values; keys stay on your
machine.

## Tests

```bash
cd FunctionApp
python3 -m pytest tests -q
```

Some of these check the app against the template rather than against itself:
that every setting the code requires is written by `deploy/azuredeploy.json`,
that every column the code sends is declared by the collection rule, and that
every directory action passes the run ceiling, the idempotency ledger and the
audit trail. Those three are the ones that fail when a change is safe in
isolation and wrong in place.

Before publishing a release, `scripts/release_gate.sh` installs the shipped
template and package into a throwaway resource group, checks that the app can
actually reach a tenant, and deletes the group again. It is the only step that
tests what a customer gets rather than what the repository contains; the header
of that file lists what it does not cover.

## Decisions that are not in the code

`docs/product-policy.md` records the choices no one can infer by reading the
source: how the shared version is numbered, how a leaked credential is stored,
and how the retention cutoff is kept away from the window being processed.
