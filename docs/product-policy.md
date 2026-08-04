# Product policy

The questions the code cannot answer. They cannot be known by reading the
source, and when they are guessed wrong the wrong product ships quietly.

**Rule**: once a policy question is answered, the answer is written here. If the
code or the docs contradict this file, **this file wins**.

**No open questions.** If a new one comes up it is added here under an
"awaiting an answer" heading.

---

## 1. Versioning

**Decision:** the release that goes out is **always `v1.0.0`**.

No new tag is cut as the code moves on; the asset on the `v1.0.0` release is
updated instead:

```bash
python3 scripts/build_package.py --out dist/FunctionApp.zip --deps-from <previous.zip>
gh release upload v1.0.0 dist/FunctionApp.zip --clobber
```

`PackageUri` never changes. Numbers like `1.1` and `1.2` are **internal
versioning**: they stay in the git history and never reach a customer. The
number only goes up in Microsoft Partner or in the Content Hub fork (the Content
Hub V3 package is a separate rule: `3.0.0`).

**Side effect, not to be skipped:** replacing the `v1.0.0` asset moves every
**running** installation bound to that URL onto the new code at its next
restart. Before doing it, look at which apps are bound to it and say so:

```bash
az functionapp config appsettings list -g <rg> -n <app> \
  --query "[?name=='WEBSITE_RUN_FROM_PACKAGE'].value" -o tsv
```

---

## 2. How a leaked credential is stored

**Decision:** the credential is recorded **exactly as SOCRadar delivered it**.
Masked or in the clear is decided in the SOCRadar platform, per company. There
is **no** second switch on the application side.

Why: a switch on both sides let the record contradict the source it came from.
If the customer asked for cleartext in SOCRadar and our setting was off, the
password never appeared in LAW and nobody knew which of the two to believe.

The `password_masked` column is derived locally either way, so a dashboard can
show something safe without ever looking at the credential.

---

## 3. First run and mutation

**Decision:** `RunOnStartup` **stays `true`**. The former sync runs as soon as
the deployment finishes, and because `FormerApplyChanges=true` it writes.

Why: the "deploy it and it works" experience is worth more than the protection a
plan-only first run would add. The protection is layered anyway: the bootstrap
run removes nothing, there are the `FormerMaxRemovals` and
`FormerMaxRemovalPercent` ceilings, and the data-completeness guard. Anyone who
wants to look at the preview deploys with Apply changes off in the form.

---

## 4. Group tenants

**Decision:** a field was added to the form for group tenants that have no
company row (`Other group tenants`, `GROUP_TENANT_IDS`).

A clarification, because the first description was wrong: cross-tenant
suppression **already worked** with a portal deployment. `derive_group_tenants()`
builds a full mesh out of the grid rows, so a company's group tenants are the
other rows' own tenants. No manual setting was needed.

The real gap was narrow: because the grid **requires** a company ID on every
row, a tenant that belongs to the group but has no company on the platform (a
holding tenant, say) could not be expressed in the grid. The new field covers
exactly that: its active members are written into every company's former list,
and it never receives a list itself.

The warning is written in the form: the app has to be consented in every tenant
listed there, otherwise the snapshot counts as incomplete and removals are
withheld.

---

## 5. Leak remediation

**Decision:** the gate is **gone**. The feature ships off by default in the
form; whoever wants it turns it on, and the responsibility is theirs.

The defaults make that safe and they are pinned to a test
(`tests/test_form_contract.py`): `EnableLeakMonitoring=false`,
`LeakResponse=logOnly`, and unless `respond` is picked the Graph write
permissions are **never requested**.

The condition that came with dropping the gate: the irreversible action has to
be written **in the form**. It was only in the README before; the customer
accepts the risk in the form, so the warning had to be there. The only truly
irreversible action is the MFA reset; the others can be undone from Entra ID and
the README's undo table shows the way.

---

## 6. Ledger growth

**Decision:** a cleanup pass that deletes old rows was added.

At the end of every apply run, rows past the retention period are deleted in a
bounded slice. The default is 90 days (`LEAK_LEDGER_RETENTION_DAYS`).

The danger runs one way: deleting a row a re-read can still reach leads to a
second action against the same person. **Two** protections together stop that;
one is not enough:

**A floor.** `MIN_RETENTION_DAYS = 30`, applied even if the setting is entered
wrong. The ongoing window is at most 24 hours, a held window is retried a few
times, and 30 days is above both.

**Active-window clamp.** The floor on its own is not enough, and the rationale
comment written first was wrong for exactly that reason.
`LeakInitialLookbackDays` is exposed in the form and can be set as high as 365.
The first run of a customer who picks 365 stamps its rows a year back; a 90-day
cutoff deletes **that run's own ledger records** and idempotency breaks on the
largest batch the installation will ever see. So the cutoff never reaches the
window being processed: `min(cutoff, active_window)`.

Verified against a real Azure Table, with the unclamped version reproduced too:
when the cutoff is not clamped, the active window's record **really is** deleted.

**UTC.** The cutoff is computed from UTC, not from the host clock. The window
stamps it compares against are produced from UTC too (`sources/base_fetcher`,
`utils/checkpoint`); a cutoff computed in local time would be a day off from the
values it filters. That every clock read in the codebase is timezone-aware is
locked down by `tests/test_utc_convention.py` (an AST scan — a literal grep
misses the variants).

If the cleanup fails the run does **not** go down with it: the rows stay and the
situation is logged. Keeping a stale row is safe; losing the run is not.

`leak/probe` writes to its own partition (`probe:<company>`) and the timer run
does not touch it. So the probe cleans its own partition when it is done, but
with a small slice (50 rows): the caller is waiting for an answer.

The setting is written by the template (`LeakLedgerRetentionDays` →
`LEAK_LEDGER_RETENTION_DAYS`), not by the form. A name the code reads and the
template does not write falls back to the default silently; even an advanced
setting has to be visible in the template.

---

## 7. Version visibility

**Decision:** not needed. An installed app will not report its own version.

If which code is running is in question, the package at
`WEBSITE_RUN_FROM_PACKAGE` is downloaded and looked at. No version constant is
kept in the code, nothing is written to LAW, and no column is added to the DCR
schema.

---

## 9. Auditability: the objectId goes into the record

**Decision:** `entra_user_id` (the Graph objectId) is written into the Log
Analytics row.

Why: the customer's first question is "did the app really do this", and they
want to confirm it from an independent source — Microsoft Entra ID's **own**
audit log. The objectId is the only field that joins the two records. Without it
the two lists cannot be put side by side.

This was **not** a privacy choice being reversed: in `_clean_record` the field
sat in the same "internal field" set as `_checkpoint_update` and
`_empty_marker`, which means it had never been thought about at all.

The trap was noted while doing it: unless the column is added to the DCR stream
as well, the rule drops it silently and the upload reports success. Both were
done together and verified live on all three leak streams.

---

## 10. Not every address in a feed goes to Graph

**Decision:** an optional "Your own email domains" field was added to the portal
form (`VerifiedDomains` → `ENTRA_ID_VERIFIED_DOMAINS`).

The code already read the setting but the template never wrote it, so it was
empty and **every address** the feed returned was queried against Microsoft
Graph, whether it had anything to do with the customer or not.

The filter runs **before** the lookup: an out-of-domain address is dropped
inside the app and never reaches Microsoft. Left empty, the old behaviour
continues exactly as before, so existing installations are not affected.

---

## 11. The first leak run comes with the deployment

**Decision:** `RUN_ON_STARTUP` was bound to the same parameter as the former
sync.

It was hardcoded `false` in the template before: a customer who turned leak
monitoring on waited for the schedule, up to 6 hours, for the first result, and
could not tell whether that was the expected behaviour or a broken deployment.
The former sync, meanwhile, ran at deployment, so the asymmetry was never
documented.

**A known and accepted side effect:** if `respond` is picked, the first run can
change real accounts at deployment time. The default is `logOnly` and the form
lists the irreversible actions, so whoever picks `respond` picks it knowingly.

---

## 12. One query surface

**Decision:** Application Insights is created bound to the Log Analytics
workspace the template creates.

As a classic component the app's traces sat in a separate resource while the
audit tables sat in the workspace. The question "the app says it did this, did
it" meant a query in two separate places and two data sets with no way to join
them.

Verified live: a single KQL query returns `AppTraces` and
`SOCRadar_EntraID_Audit_CL` together.

---

## 13. The address on a VIP record: used if it is there, never invented

**Decision.** A leak record's address is taken from the **first** field that
carries an `@` (`vipName` → `email` → `keyword`). If none of them does, there
**is no** address; the record is written with
`entra_status = skipped_no_address` and Microsoft Graph is not asked about it.

**Why.** VIP records usually name a person **by name**. In a live sample every
record's `vipName` was a first and last name, none of them carried an `@`, and
none of them had an `email` field. The old code treated `vipName` as the
address, so Graph was asked about "First Last"; Graph answers that with a 404 —
the same answer it gives for an address it has never heard of. The result: a run
that ends with `error_count = 0`, looks spotless, and **structurally cannot
match anybody**.

**Where this will not be extended.** There are addresses in the `history` field
(in half the records in the sample), but they are under the `operator`
sub-field: the address of the analyst who handled the record. In the sample not
one of them coincided with the record's own subject. Taking an address from
there points the lookup — and, if it is armed, the action — at the **wrong
person**. This is written into the code.

---

## 14. Every record falls into one bucket, and the total closes

**Decision.** `total_records` = `found_count` + `not_found_count` + `domain_filtered` +
`no_address_count` + `lookup_disabled_count` + `no_token_count` +
`lookup_failed_count`. Every record that was not looked at, or could not be, is written to its own counter.

**Why.** Before, such a record went into no bucket at all; the total was larger
than the parts and the difference had no name. Someone seeing "169 records
processed, 0 matches" on a dashboard could not tell whether they were reading
that nobody matched or that nobody was looked up.

**Side effect.** The column is declared both in the DCR stream and in the LAW
table (both are fed from the same `importAuditColumns` variable). **Existing
installations** created their own DCRs at deployment time and do not know the new
column, so the field is dropped there silently — their other counters are
unaffected, and it arrives on a redeploy.

---

## 15. An audit row only states what was actually read

**Decision.** The user lookup asks Graph for `id,userPrincipalName,accountEnabled`
**by name**. No default is **produced** for a field that does not come back; if
`entra_account_enabled` was not read, it stays empty.

**Why.** Graph returns a fixed default set of fields for `GET /users/{id}`, and
`accountEnabled` is **not** in that set. The field never arrived, and the code
filled it in with `get("accountEnabled", True)` — so for **every** matched user
it recorded "the account was enabled", without ever reading it. A disabled
account looked enabled. "Unknown" is correct; "enabled" was a guess.

---

## 16. "Did not look" and "did not find" are reported separately

**Decision.** If `leak/probe` searched no tenant at all, `apply_reason` says so
and names the reason (lookup off / no Graph token). "Not found" is only written
when a search actually happened.

**Why.** The operator's next step differs between the two: a real miss means
"the address is not in the directory", not having looked means "turn the lookup
on, or find out why no token was issued". Reporting an empty result as a
negative result is this project's recurring class of mistake.

---

## 17. The ruleset value is spelled `standard`, and the old spelling still works

**Decision.** The canonical value of `RulesetMode` / `RULESET_MODE` is
`standard`. Earlier releases spelled it `standart`, which is Turkish, and this
repository is in English. Deployments that are already running still send the
old spelling, so `config.load_former` accepts it and normalises it to
`standard`. The normalisation lives in that one function and nowhere else — a
second copy existed in `compose_company`, did nothing observable, and was
removed rather than left there implying a guarantee it was not providing.

**Where the value is visible.** Only in the `GET /api/former/preview` response,
which reports the mode a run would use. It is not stored in Log Analytics:
`build_former_audit_rows` does not carry it and the collection rule does not
declare it, so no row anywhere records either spelling. An installation still
set to the old value reports `standard` in that response after this build,
because the value is normalised before the run sees it. Nothing in a customer's
workspace changes, and no query needs to match both spellings.

**Not offered any more.** The portal form and the template only accept
`standard` and `strict`. The old spelling is accepted from an app setting, not
handed to anyone new.

---

## 8. Other constraints settled in writing

| Subject | Decision |
|---|---|
| Azure resources are shut down when a test ends | Mandatory |
| Unapproved PR or push to an external repo | Forbidden |
| `create_incident` and `ROPC` | Deliberately off in the template (comment in `main.bicep`) |
