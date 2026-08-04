# Static analysis: what it gates, what it does not

**Measurement date: 29 July 2026.** Method: ruff and mypy were run over this
repo, then both were tested against **defects actually found in this project**.
The test required evidence: the defect was reverted in a copy of the repo, the
tool was run, and the finding was checked for.

Why this question: real defects could sit there while the tests were green, and
they were found by reading the code, not by testing. So "it produces findings"
is not a reason to make a tool a gate. The question is: **does it catch what
reading found?**

## Result table

| Tool | Findings | Of those defects, caught | Verdict |
|---|---|---|---|
| ruff 0.16 | 164 (default) · 2 753 (`--select ALL`) · 2 984 (`ALL --preview`) | **0** | NOT a CI gate |
| mypy 2.3 | 34 (default) · 255 (`--strict`) | **0** | NOT a CI gate |
| coverage | 59% of production code | — | **In CI as a floor** |

`--select ALL --preview` is a superset of every selection, so the ruff verdict
does not depend on the configuration chosen. On the mypy side each mutation was
tested in its own directory, with `--no-incremental --cache-dir /dev/null`,
comparing the `(file, message)` multiset; line shifts can neither invent a
finding nor mask one.

Why: most of the defects were **missing logic** — a line that does not exist,
two gates in the wrong order, an undeclared schema column. Static analysis
inspects the code that is there; it cannot inspect code that is not. One defect
(the ARM output's lie) lives in bicep and shell, outside a Python tool's field
of view.

## It paid off anyway: a one-off run gave 3 real findings

Not being a gate does not mean "useless". The same run showed three real
problems beyond those defects:

| Finding | Where | Status |
|---|---|---|
| `date.today()` is naive, breaking the code base's UTC convention | `actions/action_ledger.py:53` | ✅ fixed |
| `except Exception: pass` swallows a lifecycle event (its own comment says it "should be alertable") | `function_app.py:1069` | ✅ fixed |
| `except Exception: pass` swallows the audit row of a failed company | `function_app.py:1213` | ✅ fixed |

So the verdict is not "do not use them": **run them by hand before a release,
do not make them a gate.**

```bash
python3 -m venv /tmp/ruff && /tmp/ruff/bin/pip install -q ruff
/tmp/ruff/bin/ruff check FunctionApp --output-format=concise
```

About 160 of the 164 findings are style or false positives. The useful part is
the `S110` (silent `except`) and `DTZ` (naive date) families; those two map
directly onto this project's documented defect class. When scanning by eye,
look at those and skip the rest.

## A closed item: naive date (and the real bug found next to it)

`cutoff_date` used `date.today()` by default; it was the **only** naive date
call in the code base. Fixed: `datetime.now(timezone.utc).date()`.

The impact would be latent today (`WEBSITE_TIME_ZONE` is not set anywhere, and
the Azure Functions Linux worker defaults to UTC). But while fixing it, a
**currently reachable** bug turned up in the same function:

I had written the rationale for `MIN_RETENTION_DAYS = 30` as "the largest
ongoing window is 24 hours". Wrong. `LeakInitialLookbackDays` is on the form and
can be set as high as 365. For a customer who picks 365, the first run stamps
its rows a year back, the 90-day cutoff deletes them, and **that run's own
idempotency records** disappear. A second action on the same person, in the
largest batch.

Fix: the cutoff never reaches into the window being processed,
`min(cutoff, active_window)`. Both call sites pass the active window.

Verified against a real Azure Table (11 checks), with a step in it that
reproduces the defect: without the clamp, the cutoff **really does** delete the
active window's record.

The convention is locked now: `tests/test_utc_convention.py` walks the whole
tree via AST (`FunctionApp/` + `scripts/`) and catches the `date.today()` ·
`datetime.date.today()` · aliased import · `utcnow` · `fromtimestamp` ·
`utcfromtimestamp` variants separately. A literal grep would miss most of them.

## Why the coverage threshold is 63

It is the production-code figure measured with `--omit='tests/*'`. Counting the
tests inflates the number, because test files by definition run almost entirely
— putting a floor on that number would produce an indicator that rises when you
write a test but covers not one line of application code.

The threshold is **a floor, not a target**: it exists so the number does not go
backwards. It is raised if it is genuinely exceeded, and never lowered to let a
branch pass. It was 59 when first set; once the Graph mutation results were tied
to tests, production coverage rose to 63 and the floor was raised with it. It
was verified to break: the threshold value passes, one above it exits 2.

The least-covered places and why they mattered:

| Module | Coverage | What a defect there does |
|---|---|---|
| `actions/entra_id.py` | 23% → **56%** | Every real Graph mutation happens here. If a status-code check slips by one, a 403 counts as success, the ledger writes "done", and nobody retries the untouched account again. Closed with `tests/test_graph_mutation_results.py`: 11 rejection codes × 7 wrappers, plus transport errors, plus keeping the "already in the requested state" exception narrow. 4/4 mutations caught |
| `actions/former_lock.py` | 38% | The ETag takeover race; if the lock breaks, a manual add lands in the middle of an apply-mode readback and corrupts the ownership accounting |
| `utils/checkpoint.py` | 40% | `save()` filters fields; if a field silently drops, the next run resumes from the wrong window |
| `actions/former_ownership.py` | 53% | The gate that decides which account is "ours"; if it inverts, somebody else's record gets deleted |

This table is not for raising the threshold, it is for choosing **which test is
worth writing**. Chasing the percentage did not work in this repo.
