"""The idempotency ledger has to forget, but never too early.

Rows accumulate for the life of a deployment: one per (person, action,
window). Nothing removed them, so a company running six-hourly grows the table
forever. The cleanup added for that has one way to cause real harm — dropping a
row a re-read can still reach, which would let the same person be acted on
twice — so the floor and the boundary are what these tests hold down.
"""

import sys
import unittest
from datetime import date
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from test_import_path import _ensure_azure_stub  # noqa: E402

_ensure_azure_stub()

from actions import action_ledger as led  # noqa: E402
import function_app  # noqa: E402


class CutoffDateTest(unittest.TestCase):

    def test_retention_is_counted_back_from_today(self):
        self.assertEqual(led.cutoff_date(90, today=date(2026, 7, 29)),
                         "2026-04-30")

    def test_zero_retention_is_floored(self):
        """A retention of 0 would purge the window currently being processed
        and turn every run into a repeat of the last one."""
        self.assertEqual(led.cutoff_date(0, today=date(2026, 7, 29)),
                         led.cutoff_date(led.MIN_RETENTION_DAYS,
                                         today=date(2026, 7, 29)))

    def test_negative_retention_is_floored(self):
        self.assertEqual(led.cutoff_date(-500, today=date(2026, 7, 29)),
                         led.cutoff_date(led.MIN_RETENTION_DAYS,
                                         today=date(2026, 7, 29)))

    def test_unparseable_retention_is_floored(self):
        """App settings arrive as strings; a typo must not disable the floor."""
        self.assertEqual(led.cutoff_date("ninety", today=date(2026, 7, 29)),
                         led.cutoff_date(led.MIN_RETENTION_DAYS,
                                         today=date(2026, 7, 29)))

    def test_numeric_string_is_honoured(self):
        self.assertEqual(led.cutoff_date("90", today=date(2026, 7, 29)),
                         "2026-04-30")

    def test_floor_is_wider_than_the_longest_ongoing_window(self):
        """Ongoing windows are at most 24h and a held window retries a few
        times. Thirty days leaves that untouched with room to spare."""
        self.assertGreaterEqual(led.MIN_RETENTION_DAYS, 30)


class ActiveWindowClampTest(unittest.TestCase):
    """A first run may look back as far as LeakInitialLookbackDays, and the
    portal form offers 365. Those rows are stamped a year back -- older than any
    retention -- so an unclamped cutoff deletes the idempotency records of the
    run that is writing them, on the largest batch the deployment will ever
    process. The 30-day floor cannot help: the window is outside it by design.
    """

    TODAY = date(2026, 7, 30)

    def test_a_window_older_than_the_cutoff_pulls_it_back(self):
        cutoff = led.cutoff_date(90, today=self.TODAY,
                                 active_window="2025-08-01")
        self.assertEqual(cutoff, "2025-08-01")

    def test_a_recent_window_leaves_the_cutoff_alone(self):
        """The clamp must not shorten retention on an ordinary run."""
        cutoff = led.cutoff_date(90, today=self.TODAY,
                                 active_window="2026-07-30")
        self.assertEqual(cutoff, "2026-05-01")

    def test_without_an_active_window_the_retention_stands(self):
        self.assertEqual(led.cutoff_date(90, today=self.TODAY), "2026-05-01")

    def test_the_clamped_cutoff_spares_the_window_being_processed(self):
        """End to end: the rows this run just wrote survive its own purge."""
        ledger = led.InMemoryActionLedger()
        ledger.record_applied("deep@x.com", "botnet", "revoke_session",
                              "2025-08-01")
        ledger.record_applied("older@x.com", "botnet", "revoke_session",
                              "2025-07-01")
        cutoff = led.cutoff_date(90, today=self.TODAY,
                                 active_window="2025-08-01")
        ledger.purge_before(cutoff)
        self.assertTrue(ledger.already_applied(
            "deep@x.com", "botnet", "revoke_session", "2025-08-01"),
            "the active window's own records were deleted")
        self.assertFalse(ledger.already_applied(
            "older@x.com", "botnet", "revoke_session", "2025-07-01"),
            "genuinely stale rows should still go")

    def test_the_floor_still_applies_under_the_clamp(self):
        """Both protections at once, neither cancelling the other."""
        cutoff = led.cutoff_date(0, today=self.TODAY,
                                 active_window="2026-07-30")
        self.assertEqual(cutoff, "2026-06-30")


class InMemoryPurgeTest(unittest.TestCase):

    def _ledger(self):
        ledger = led.InMemoryActionLedger()
        for day in ("2026-01-01", "2026-04-29", "2026-04-30", "2026-07-29"):
            ledger.record_applied(f"a{day}@x.com", "botnet",
                                  "revoke_session", day)
        return ledger

    def test_older_windows_are_dropped(self):
        ledger = self._ledger()
        self.assertEqual(ledger.purge_before("2026-04-30"), 2)

    def test_the_cutoff_day_itself_is_kept(self):
        """lt, not lte: the boundary day is still reachable."""
        ledger = self._ledger()
        ledger.purge_before("2026-04-30")
        self.assertTrue(ledger.already_applied(
            "a2026-04-30@x.com", "botnet", "revoke_session", "2026-04-30"))

    def test_a_purged_window_no_longer_blocks(self):
        """The point of removing a row: it stops being an idempotency record."""
        ledger = self._ledger()
        ledger.purge_before("2026-04-30")
        self.assertFalse(ledger.already_applied(
            "a2026-01-01@x.com", "botnet", "revoke_session", "2026-01-01"))

    def test_recent_window_survives(self):
        ledger = self._ledger()
        ledger.purge_before("2026-04-30")
        self.assertTrue(ledger.already_applied(
            "a2026-07-29@x.com", "botnet", "revoke_session", "2026-07-29"))

    def test_max_rows_bounds_one_pass(self):
        ledger = self._ledger()
        self.assertEqual(ledger.purge_before("2026-07-29", max_rows=1), 1)


class _FakeTable:
    """Stands in for the Azure table client. Records the filter it was asked
    for, so the test can assert on the query rather than trusting it."""

    def __init__(self, rows, fail_on=()):
        self.rows = list(rows)
        self.deleted = []
        self.queries = []
        self._fail_on = set(fail_on)

    def query_entities(self, query, select=None):
        self.queries.append(query)
        return list(self.rows)

    def delete_entity(self, partition, row_key):
        if row_key in self._fail_on:
            from azure.core.exceptions import ResourceNotFoundError
            raise ResourceNotFoundError("gone")
        self.deleted.append((partition, row_key))


def _table_ledger(rows, fail_on=()):
    """An ActionLedger wired to a fake table. Built without __init__ on
    purpose: the real one opens a TableServiceClient."""
    ledger = object.__new__(led.ActionLedger)
    ledger._table = _FakeTable(rows, fail_on=fail_on)
    ledger._partition = "botnet:1234567"
    return ledger


class TablePurgeTest(unittest.TestCase):

    def _rows(self, n):
        return [{"PartitionKey": "botnet:1234567", "RowKey": f"rk{i}"}
                for i in range(n)]

    def test_query_is_scoped_to_this_partition_and_older_windows(self):
        """A filter missing either half would delete another company's rows,
        or rows the current window still needs."""
        ledger = _table_ledger(self._rows(1))
        ledger.purge_before("2026-04-30")
        query = ledger._table.queries[0]
        self.assertIn("PartitionKey eq 'botnet:1234567'", query)
        self.assertIn("window_date lt '2026-04-30'", query)

    def test_every_returned_row_is_deleted(self):
        ledger = _table_ledger(self._rows(3))
        self.assertEqual(ledger.purge_before("2026-04-30"), 3)
        self.assertEqual(len(ledger._table.deleted), 3)

    def test_max_rows_stops_the_pass(self):
        """A year-old deployment has a large backlog; draining it in one run
        would eat the run's time slot."""
        ledger = _table_ledger(self._rows(10))
        self.assertEqual(ledger.purge_before("2026-04-30", max_rows=4), 4)
        self.assertEqual(len(ledger._table.deleted), 4)

    def test_a_row_deleted_by_another_run_is_not_an_error(self):
        ledger = _table_ledger(self._rows(3), fail_on={"rk1"})
        self.assertEqual(ledger.purge_before("2026-04-30"), 2)


def _conf(**over):
    conf = {
        "storage_account_name": "sa",
        "socradar_api_key": "k", "socradar_company_id": "1234567",
        "socradar_base_url": "https://example.invalid",
        "enable_user_lookup": True, "verified_domains": [],
        "enable_create_incident": False, "enable_resolve_alarm": False,
        "enable_ropc": False, "entra_action_mode": "apply",
        "entra_max_actions_per_run": 50, "security_group_id": "",
        "enable_revoke_session": True, "enable_add_to_group": False,
        "enable_remove_from_group": False, "enable_password_change": False,
        "enable_disable_account": False, "enable_enable_account": False,
        "enable_confirm_risky": False, "enable_force_mfa_reregistration": False,
        "initial_lookback_minutes": 43200, "initial_start_date": "2026-07-27",
        "max_pages_per_run": 50, "leak_ledger_retention_days": 90,
    }
    conf.update(over)
    return conf


class _RecordingLedger(led.InMemoryActionLedger):
    def __init__(self):
        super().__init__()
        self.purges = []

    def purge_before(self, cutoff, max_rows=500):
        self.purges.append(cutoff)
        return super().purge_before(cutoff, max_rows)


class _ExplodingLedger(led.InMemoryActionLedger):
    def purge_before(self, cutoff, max_rows=500):
        raise RuntimeError("table unreachable")


def _run(conf, ledger):
    with mock.patch.object(function_app.src_botnet, "fetch",
                           return_value=[{"email": "alice@x.com"}]), \
         mock.patch.object(function_app.cp, "load", return_value={}), \
         mock.patch.object(function_app.cp, "save"), \
         mock.patch.object(function_app.law, "write_records", return_value=True), \
         mock.patch.object(function_app.entra, "lookup_user",
                           return_value=({"id": "uid", "accountEnabled": True}, 200)), \
         mock.patch.object(function_app.entra, "revoke_sessions", return_value=True), \
         mock.patch.object(function_app.ledger_mod, "ActionLedger",
                           return_value=ledger), \
         mock.patch.object(function_app.ledger_mod, "InMemoryActionLedger",
                           return_value=ledger):
        return function_app._process_source(
            "botnet", conf, None, {"t-a": {"h": "x"}},
            deadline=float("inf"), checkpoint_key="botnet:1234567")


class RunWiringTest(unittest.TestCase):

    def test_an_apply_run_cleans_up(self):
        """Without this call the table only ever grows."""
        ledger = _RecordingLedger()
        _run(_conf(), ledger)
        self.assertEqual(len(ledger.purges), 1)

    def test_the_cutoff_comes_from_the_configured_retention(self):
        ledger = _RecordingLedger()
        _run(_conf(leak_ledger_retention_days=365), ledger)
        self.assertEqual(ledger.purges[0], led.cutoff_date(365))

    def test_the_run_clamps_to_the_window_it_is_processing(self):
        """The clamp only helps if the run actually passes its window in. With
        a year-deep first window and a 90-day retention, an unclamped cutoff
        would land in 2026 and wipe the 2025 rows this run is writing."""
        ledger = _RecordingLedger()
        _run(_conf(initial_start_date="2025-08-01",
                   leak_ledger_retention_days=90), ledger)
        self.assertEqual(ledger.purges, ["2025-08-01"])

    def test_a_plan_run_does_not_clean_up(self):
        """Plan mode writes nothing, so it has nothing to clean and no
        business deleting an apply run's records."""
        ledger = _RecordingLedger()
        _run(_conf(entra_action_mode="plan"), ledger)
        self.assertEqual(ledger.purges, [])

    def test_a_failing_cleanup_does_not_fail_the_run(self):
        """Keeping stale rows is safe. Losing the run's results is not."""
        result = _run(_conf(), _ExplodingLedger())
        self.assertEqual(result["source"], "botnet")
        self.assertEqual(result["errors"], 0)


class ProbePartitionTest(unittest.TestCase):
    """The probe endpoint writes to its own partition, which no timer run
    touches. Without a cleanup of its own it is the one place the table still
    grows forever."""

    def test_the_probe_path_cleans_its_own_partition(self):
        source = Path(function_app.__file__).read_text()
        start = source.index("def leak_probe")
        body = source[start:start + 8000]
        self.assertIn("purge_before", body,
                      "probe rows are written to 'probe:<company>' and no "
                      "other code path removes them")

    def test_the_probe_clamps_too_even_though_it_cannot_bite_today(self):
        """Stated plainly: the probe stamps its rows with today's date, and the
        cutoff is always at least thirty days back, so min() can never choose
        the window here. The clamp is present for two reasons -- one call site
        clamping and the other not is a question a reader should not have to
        ask, and if the probe ever accepts a window parameter the arithmetic is
        already right. This is a source-level assertion because there is no
        behaviour to observe; pretending otherwise would be a test that proves
        nothing."""
        source = Path(function_app.__file__).read_text()
        start = source.index("def leak_probe")
        body = source[start:start + 8000]
        self.assertIn("active_window=window_date", body)

    def test_the_probe_cleanup_is_a_small_slice(self):
        """A synchronous request the caller waits on; a 500-row drain would
        be felt. Matched with the closing paren on purpose: 'max_rows=50' is a
        substring of 'max_rows=500', so the looser check passes either way."""
        source = Path(function_app.__file__).read_text()
        start = source.index("def leak_probe")
        body = source[start:start + 8000]
        self.assertIn("max_rows=50)", body)


if __name__ == "__main__":
    unittest.main()
