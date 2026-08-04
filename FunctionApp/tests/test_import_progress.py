"""A run must always move forward: fetching may not consume the whole slot.

Observed live: botnet pulled 2564 records in 90s while the slot was 80s, so no
record was ever looked up, the checkpoint was held back, and the next run did
exactly the same thing. Two consecutive runs, zero progress.
"""

import sys
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from test_import_path import _ensure_azure_stub  # noqa: E402

_ensure_azure_stub()

import function_app  # noqa: E402
from sources import botnet  # noqa: E402


def _conf(**over):
    conf = {
        "storage_account_name": "sa",
        "socradar_api_key": "k", "socradar_company_id": "1234567",
        "socradar_base_url": "https://example.invalid",
        "enable_user_lookup": False,
        "verified_domains": [],
        "enable_create_incident": False, "enable_resolve_alarm": False,
        "entra_action_mode": "plan", "entra_max_actions_per_run": 50,
        "initial_lookback_minutes": 43200, "initial_start_date": "",
        "max_pages_per_run": 50,
    }
    conf.update(over)
    return conf


class _Page:
    """A feed page that takes measurable time to return."""

    def __init__(self, total_pages, seconds):
        self.total_pages = total_pages
        self.seconds = seconds
        self.status_code = 200

    def json(self):
        return {
            "is_success": True,
            "data": {
                "total_pages": self.total_pages,
                "total_data_count": self.total_pages * 100,
                "data": [{"email": f"u{i}@x.com", "isEmployee": True} for i in range(100)],
            },
        }


class FetchBudgetTest(unittest.TestCase):
    def test_fetch_stops_at_its_deadline(self):
        """A long feed must not swallow the whole window."""
        clock = {"t": 1000.0}

        def fake_get(*_a, **_k):
            clock["t"] += 10.0          # each page costs 10s
            return _Page(total_pages=50, seconds=10)

        with mock.patch.object(botnet.requests, "get", side_effect=fake_get), \
             mock.patch.object(botnet.time, "time", side_effect=lambda: clock["t"]):
            records = botnet.fetch(_conf(), {}, deadline=1035.0)  # 35s of room

        # Roughly 3-4 pages fit in 35s; certainly not all 50.
        self.assertLess(len(records), 50 * 100)
        self.assertGreater(len(records), 0)

    def test_interrupted_fetch_does_not_claim_completion(self):
        """Stopping early must leave the checkpoint pointing at the next page,
        not at today — otherwise the unread backlog is skipped."""
        clock = {"t": 1000.0}

        def fake_get(*_a, **_k):
            clock["t"] += 10.0
            return _Page(total_pages=50, seconds=10)

        with mock.patch.object(botnet.requests, "get", side_effect=fake_get), \
             mock.patch.object(botnet.time, "time", side_effect=lambda: clock["t"]):
            records = botnet.fetch(_conf(), {}, deadline=1035.0)

        chk = records[-1].get("_checkpoint_update") or {}
        self.assertGreater(chk.get("last_page", 0), 0,
                           "an interrupted fetch must resume from its page")

    def test_a_complete_fetch_still_advances_the_date(self):
        clock = {"t": 1000.0}

        def fake_get(*_a, **_k):
            clock["t"] += 0.1
            return _Page(total_pages=2, seconds=0.1)

        with mock.patch.object(botnet.requests, "get", side_effect=fake_get), \
             mock.patch.object(botnet.time, "time", side_effect=lambda: clock["t"]):
            records = botnet.fetch(_conf(), {}, deadline=2000.0)

        chk = records[-1].get("_checkpoint_update") or {}
        self.assertEqual(chk.get("last_page"), 0, "a finished fetch resets the page")

    def test_page_cap_comes_from_config(self):
        clock = {"t": 1000.0}

        def fake_get(*_a, **_k):
            clock["t"] += 0.1
            return _Page(total_pages=50, seconds=0.1)

        with mock.patch.object(botnet.requests, "get", side_effect=fake_get), \
             mock.patch.object(botnet.time, "time", side_effect=lambda: clock["t"]):
            records = botnet.fetch(_conf(max_pages_per_run=3), {}, deadline=9000.0)

        self.assertEqual(len(records), 300)  # 3 pages x 100


class SlotSplitTest(unittest.TestCase):
    def _capture(self, conf, slot_seconds=100):
        seen = {}

        def fake_fetch(conf_, chk, deadline=None, max_records=None):
            seen["fetch_deadline"] = deadline
            seen["max_records"] = max_records
            return [{"email": "a@x.com", "_checkpoint_update": {"last_start_date": "2026-07-27"}}]

        slot_deadline = time.time() + slot_seconds
        with mock.patch.object(function_app.src_botnet, "fetch", side_effect=fake_fetch), \
             mock.patch.object(function_app.cp, "load", return_value={}), \
             mock.patch.object(function_app.cp, "save"), \
             mock.patch.object(function_app.law, "write_records"), \
             mock.patch.object(function_app.entra, "lookup_user", return_value=(None, 404)):
            function_app._process_source("botnet", conf, None, {"t": {"h": "x"}},
                                         deadline=slot_deadline, checkpoint_key="botnet:1234567")
        seen["slot_deadline"] = slot_deadline
        return seen

    def test_process_source_reserves_time_for_lookups(self):
        """The fetch deadline handed down must be earlier than the slot's own."""
        seen = self._capture(_conf())
        self.assertIsNotNone(seen["fetch_deadline"])
        self.assertLess(seen["fetch_deadline"], seen["slot_deadline"],
                        "fetching must not be allowed to use the whole slot")

    def test_fetch_is_sized_to_what_the_run_can_look_up(self):
        """With lookups on, the fetch is capped by processing capacity —
        otherwise a big pull is fetched and only a fraction of it processed."""
        seen = self._capture(_conf(enable_user_lookup=True), slot_seconds=100)
        cap = seen["max_records"]
        self.assertIsNotNone(cap)
        # 100s slot, 60% for lookups at ~0.4s each => roughly 150 records
        self.assertLess(cap, 1000, "capacity cap must be well under a full backlog")
        self.assertGreaterEqual(cap, function_app.PAGE_MIN_RECORDS)

    def test_no_cap_when_lookups_are_off(self):
        """Without Graph lookups the records are only written to LAW, which is
        fast, so there is no reason to hold the fetch back."""
        seen = self._capture(_conf(enable_user_lookup=False))
        self.assertIsNone(seen["max_records"])

    def test_infinite_slot_does_not_break_the_cap(self):
        seen = self._capture(_conf(enable_user_lookup=True), slot_seconds=float("inf"))
        self.assertIsInstance(seen["max_records"], int)


if __name__ == "__main__":
    unittest.main()
