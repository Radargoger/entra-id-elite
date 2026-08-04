"""Two ways a run could be wrong without anybody being able to see it.

The window's identity has to survive a run that held it, or the ledger stops
recognising a repeat and the same person is acted on twice. And a company that
fell out of the configuration has to appear in the audit trail as absent,
rather than simply not appear.
"""

import sys
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import test_import_path  # noqa: E402,F401  (installs the azure stubs)
import function_app  # noqa: E402
from utils import checkpoint as cp  # noqa: E402

LOOKBACK = 43200  # thirty days, the shipped default


class AWindowAHeldRunLeftOpen(unittest.TestCase):
    """Recomputing the start from the lookback moves it a day per run."""

    def _start_on(self, day, checkpoint):
        frozen = datetime.fromisoformat(day).replace(tzinfo=timezone.utc)

        class _DT(datetime):
            @classmethod
            def now(cls, tz=None):
                return frozen

        with mock.patch.object(cp, "datetime", _DT):
            return cp.get_start_date(checkpoint, LOOKBACK, "")

    def test_an_unpinned_window_drifts(self):
        # The behaviour being guarded against, stated so the guard cannot be
        # read as testing nothing.
        first = self._start_on("2026-07-30", {"consecutive_holds": 1})
        second = self._start_on("2026-07-31", {"consecutive_holds": 1})
        self.assertNotEqual(first, second)

    def test_a_pinned_window_does_not(self):
        held = {"consecutive_holds": 1, "active_window_start": "2026-06-30"}
        self.assertEqual(self._start_on("2026-07-30", held), "2026-06-30")
        self.assertEqual(self._start_on("2026-08-15", held), "2026-06-30")

    def test_a_finished_window_still_wins(self):
        both = {"last_start_date": "2026-07-20", "active_window_start": "2026-06-30"}
        self.assertEqual(self._start_on("2026-07-31", both), "2026-07-20")

    def test_an_explicit_start_date_is_used_when_nothing_is_pinned(self):
        with mock.patch.object(cp, "datetime", datetime):
            self.assertEqual(cp.get_start_date({}, LOOKBACK, "2025-01-01"), "2025-01-01")


class WhatARunWritesAboutItsWindow(unittest.TestCase):
    """The pin is set when a run holds, and released when it finishes."""

    def _run(self, employees, conf_over=None, tenants=None):
        conf = {
            "storage_account_name": "sa", "enable_user_lookup": True,
            "verified_domains": [], "enable_create_incident": False,
            "enable_resolve_alarm": False, "socradar_api_key": "k",
            "socradar_company_id": "1", "entra_action_mode": "plan",
        }
        conf.update(conf_over or {})
        with mock.patch.object(function_app.src_botnet, "fetch", return_value=employees), \
             mock.patch.object(function_app.cp, "load", return_value={}), \
             mock.patch.object(function_app.cp, "save") as save, \
             mock.patch.object(function_app.law, "write_records"):
            function_app._process_source("botnet", conf, None, tenants or {},
                                         deadline=time.time() + 3600,
                                         checkpoint_key="botnet:1")
        return save.call_args[0][3] if save.call_args else {}

    def test_a_held_run_pins_the_window_it_could_not_finish(self):
        rows = [{"email": "u@example.com"}]
        rows[-1]["_checkpoint_update"] = {"last_start_date": "2026-07-30"}
        saved = self._run(rows)  # no tenant token -> holds
        self.assertNotIn("last_start_date", saved)
        self.assertTrue(saved.get("active_window_start"),
                        "the next run will recompute a different window and the "
                        "ledger will not recognise the repeat")

    def test_a_finished_run_releases_the_pin(self):
        rows = [{"email": "u@example.com"}]
        rows[-1]["_checkpoint_update"] = {"last_start_date": "2026-07-30"}
        saved = self._run(rows, conf_over={"enable_user_lookup": False})
        self.assertEqual(saved.get("last_start_date"), "2026-07-30")
        self.assertEqual(saved.get("active_window_start"), "",
                         "a stale pin would freeze the window for good")


class ACompanyThatFellOutOfTheConfiguration(unittest.TestCase):
    """A dropped row is a company nobody looked at. It has to say so."""

    GOOD = ('[{"companyId":"1","tenantIds":"t1","apiKey":"k"},'
            ' "this row is not an object"]')

    def _rows(self, raw):
        conf = {"company_map_raw": raw, "dcr_immutable_id": "id",
                "dcr_endpoint": "https://dce.test"}
        with mock.patch.object(function_app.law, "write_lifecycle_event") as event:
            rows = function_app._import_company_rows(conf)
        return rows, event

    def test_the_usable_rows_still_run(self):
        rows, _ = self._rows(self.GOOD)
        self.assertEqual([r["company_id"] for r in rows], ["1"])

    def test_the_dropped_row_reaches_the_audit_trail(self):
        _, event = self._rows(self.GOOD)
        self.assertTrue(
            event.called,
            "the only trace of a company being skipped was a log line, and the "
            "run reported a clean sweep of the companies that were left")
        self.assertEqual(event.call_args.kwargs.get("event_type"), "company_row_dropped")

    def test_a_clean_map_stays_quiet(self):
        _, event = self._rows('[{"companyId":"1","tenantIds":"t1","apiKey":"k"}]')
        self.assertFalse(event.called)

    def test_a_map_with_nothing_usable_still_stops_the_run(self):
        with self.assertRaises(RuntimeError):
            self._rows('["only garbage"]')


if __name__ == "__main__":
    unittest.main()
