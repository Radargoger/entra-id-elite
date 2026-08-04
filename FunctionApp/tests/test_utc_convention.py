"""Every clock reading in this repository has to be timezone-aware.

The dates this app computes are compared against each other: a leak window is
stamped in UTC (sources/base_fetcher), a checkpoint start is derived in UTC
(utils/checkpoint), and the ledger retention cutoff filters on those stamps. One
naive reading among them puts the comparison a day out on any host whose clock
is not UTC, and nothing about that failure is loud -- rows are dropped or kept
silently, and the app reports a normal run either way.

Written as an AST walk rather than a grep on purpose. A grep for `date.today()`
passes happily on `datetime.date.today()`, on `import datetime as dt;
dt.date.today()`, and on `utcfromtimestamp`, all of which are the same defect
with different spelling -- and this project has already shipped a compliance
gate that reported clean because its pattern, not the code, was wrong.
"""

import ast
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

# Directories that ship or run. tests/ and scripts/ are included deliberately:
# both are clean today, so requiring them costs nothing and stops the
# convention decaying at the edges.
ROOTS = ["FunctionApp", "scripts"]

# Call names that read a clock. `fromtimestamp` is here because it is naive
# unless a tz is supplied, and `utcnow`/`utcfromtimestamp` because they return
# a naive datetime that merely happens to hold UTC -- the source of a whole
# family of off-by-one-day bugs.
CLOCK_CALLS = {"today", "now", "utcnow", "fromtimestamp", "utcfromtimestamp"}

# These are naive whatever the arguments: no parameter can make them aware.
ALWAYS_NAIVE = {"today", "utcnow", "utcfromtimestamp"}


def _is_aware(call: ast.Call, name: str) -> bool:
    """True when this call supplies a timezone."""
    if name in ALWAYS_NAIVE:
        return False
    for kw in call.keywords:
        if kw.arg in ("tz", "tzinfo"):
            return True
    # datetime.now(timezone.utc) and datetime.fromtimestamp(ts, timezone.utc)
    positional_tz_index = {"now": 0, "fromtimestamp": 1}[name]
    return len(call.args) > positional_tz_index


def _naive_clock_calls(source: str):
    """(line, spelling) for every timezone-naive clock reading."""
    found = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not isinstance(func, ast.Attribute) or func.attr not in CLOCK_CALLS:
            continue
        name = func.attr
        if _is_aware(node, name):
            continue
        # Render the receiver for the message: date, datetime, dt.date, ...
        parts, cursor = [name], func.value
        while isinstance(cursor, ast.Attribute):
            parts.insert(0, cursor.attr)
            cursor = cursor.value
        if isinstance(cursor, ast.Name):
            parts.insert(0, cursor.id)
        found.append((node.lineno, ".".join(parts) + "()"))
    return found


def _python_files():
    for root in ROOTS:
        for path in sorted((REPO / root).rglob("*.py")):
            if "__pycache__" in path.parts or ".venv" in path.parts:
                continue
            if ".python_packages" in path.parts:
                continue
            yield path


class UtcConventionTest(unittest.TestCase):

    def test_no_naive_clock_reading_anywhere(self):
        offenders = []
        for path in _python_files():
            for line, spelling in _naive_clock_calls(path.read_text()):
                offenders.append(f"{path.relative_to(REPO)}:{line}  {spelling}")
        self.assertEqual(
            offenders, [],
            "timezone-naive clock reading(s); use datetime.now(timezone.utc):\n  "
            + "\n  ".join(offenders))

    def test_the_files_really_were_scanned(self):
        """A walk that silently matched nothing would make the test above pass
        by accident -- a false-clean scan can start exactly that way."""
        self.assertGreater(len(list(_python_files())), 30)


class DetectorTest(unittest.TestCase):
    """The detector is the thing being trusted, so it is tested against every
    spelling it is supposed to catch and every one it must not flag."""

    def _lines(self, source):
        return [s for _, s in _naive_clock_calls(source)]

    def test_catches_plain_date_today(self):
        self.assertEqual(self._lines("import datetime\nx = date.today()\n"),
                         ["date.today()"])

    def test_catches_module_qualified_date_today(self):
        self.assertEqual(self._lines("import datetime\nx = datetime.date.today()\n"),
                         ["datetime.date.today()"])

    def test_catches_aliased_import(self):
        """The spelling a grep written against `date.today()` walks straight past."""
        self.assertEqual(self._lines("import datetime as dt\nx = dt.date.today()\n"),
                         ["dt.date.today()"])

    def test_catches_naive_now(self):
        self.assertEqual(self._lines("x = datetime.now()\n"), ["datetime.now()"])

    def test_catches_utcnow(self):
        """Returns UTC as a naive value, which is how the day-off bugs start."""
        self.assertEqual(self._lines("x = datetime.utcnow()\n"), ["datetime.utcnow()"])

    def test_catches_naive_fromtimestamp(self):
        self.assertEqual(self._lines("x = datetime.fromtimestamp(ts)\n"),
                         ["datetime.fromtimestamp(ts)".replace("(ts)", "()")])

    def test_catches_utcfromtimestamp(self):
        self.assertEqual(self._lines("x = datetime.utcfromtimestamp(ts)\n"),
                         ["datetime.utcfromtimestamp()"])

    def test_accepts_positional_timezone(self):
        self.assertEqual(self._lines("x = datetime.now(timezone.utc)\n"), [])

    def test_accepts_keyword_timezone(self):
        self.assertEqual(self._lines("x = datetime.now(tz=timezone.utc)\n"), [])

    def test_accepts_aware_fromtimestamp(self):
        self.assertEqual(self._lines("x = datetime.fromtimestamp(ts, timezone.utc)\n"), [])

    def test_ignores_unrelated_calls_named_now(self):
        """`now` on something that is not a clock must not be reported."""
        self.assertEqual(self._lines("x = progress.now(step)\n"), [])


if __name__ == "__main__":
    unittest.main()
