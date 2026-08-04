"""A window may only be retired once something actually looked at it.

Every case here is one where the run produced no error anybody could see and
advanced the checkpoint anyway, so the findings inside that window were never
fetched again. They are grouped together because they share that shape, not
because they share a code path.
"""

import datetime as dt
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import test_import_path  # noqa: E402,F401  (installs the azure stubs)
import function_app  # noqa: E402
from sources.base_fetcher import BaseFetcher  # noqa: E402


def _conf(**over):
    conf = {
        "storage_account_name": "sa",
        "enable_user_lookup": True,
        "verified_domains": [],
        "enable_create_incident": False,
        "enable_resolve_alarm": False,
        "socradar_api_key": "k",
        "socradar_company_id": "1",
        "entra_action_mode": "plan",
    }
    conf.update(over)
    return conf


def _employees(n, checkpoint):
    rows = [{"email": f"u{i}@example.com"} for i in range(n)]
    rows[-1]["_checkpoint_update"] = checkpoint
    return rows


def _run_source(employees, conf, tenant_headers_map):
    with mock.patch.object(function_app.src_botnet, "fetch", return_value=employees), \
         mock.patch.object(function_app.cp, "load", return_value={}), \
         mock.patch.object(function_app.cp, "save") as save, \
         mock.patch.object(function_app.law, "write_records"):
        audit = function_app._process_source(
            "botnet", conf, None, tenant_headers_map,
            deadline=time.time() + 3600, checkpoint_key="botnet:1")
    saved = save.call_args[0][3] if save.call_args else {}
    return audit, saved


class AWindowNobodyCouldLookUp(unittest.TestCase):
    """No tenant produced a Graph token, so nothing in the window was checked."""

    def setUp(self):
        self.audit, self.saved = _run_source(
            _employees(5, {"last_start_date": "2026-07-30"}), _conf(), {})

    def test_the_window_is_not_retired(self):
        self.assertNotIn(
            "last_start_date", self.saved,
            "the window advanced although no record in it was ever looked up")

    def test_the_run_says_it_could_not_look(self):
        self.assertEqual(self.audit["no_token"], 5)

    def test_the_hold_is_counted_so_the_escape_can_arm(self):
        # Holding forever is its own failure; MAX_CONSECUTIVE_HOLDS needs this
        # to be persisted or it can never trip.
        self.assertEqual(self.saved.get("consecutive_holds"), 1)


class AWindowTheOperatorChoseNotToLookUp(unittest.TestCase):
    """Lookup switched off is a choice, not a failure — the window may move on."""

    def setUp(self):
        self.audit, self.saved = _run_source(
            _employees(5, {"last_start_date": "2026-07-30"}),
            _conf(enable_user_lookup=False), {})

    def test_the_window_advances(self):
        self.assertEqual(self.saved.get("last_start_date"), "2026-07-30")

    def test_those_records_still_have_a_name(self):
        self.assertEqual(self.audit["lookup_disabled"], 5)


class TheAuditRowAddsUp(unittest.TestCase):
    """total is the sum of the named buckets, in every disposition."""

    def _check(self, audit):
        parts = (audit["found"] + audit["not_found"] + audit["no_address"]
                 + audit["domain_filtered"] + audit["lookup_disabled"]
                 + audit["no_token"])
        self.assertEqual(
            audit["total"], parts,
            f"{audit['total'] - parts} record(s) left the run with no bucket: {audit}")

    def test_when_no_token_was_available(self):
        audit, _ = _run_source(_employees(5, {"last_start_date": "2026-07-30"}), _conf(), {})
        self._check(audit)

    def test_when_lookup_is_disabled(self):
        audit, _ = _run_source(_employees(5, {"last_start_date": "2026-07-30"}),
                               _conf(enable_user_lookup=False), {})
        self._check(audit)

    def test_when_the_domain_allowlist_rejects_everything(self):
        audit, _ = _run_source(_employees(5, {"last_start_date": "2026-07-30"}),
                               _conf(verified_domains=["other.test"]), {})
        self._check(audit)

    def test_when_records_carry_no_address(self):
        rows = [{"email": ""} for _ in range(3)]
        rows[-1]["_checkpoint_update"] = {"last_start_date": "2026-07-30"}
        audit, _ = _run_source(rows, _conf(), {})
        self._check(audit)


class AnEmptyFetchIsNotAFinding(unittest.TestCase):
    """The marker is bookkeeping. Counting it filed an empty run as a person."""

    def setUp(self):
        marker = [{"_checkpoint_update": {"last_start_date": "2026-07-30"},
                   "_empty_marker": True, "_fetch_failed": False}]
        self.audit, self.saved = _run_source(marker, _conf(), {})

    def test_it_is_not_counted_as_an_address_less_record(self):
        self.assertEqual(self.audit["no_address"], 0)

    def test_the_row_still_adds_up(self):
        self.assertEqual(self.audit["total"], 0)
        self.assertEqual(self.audit["no_address"] + self.audit["found"]
                         + self.audit["not_found"], 0)


class AFeedThatBrokeMidStream(unittest.TestCase):
    """The failure signal has to reach the caller even when pages arrived."""

    def test_the_window_is_held_and_the_run_reports_an_error(self):
        rows = _employees(3, {"last_start_date": "2026-07-30"})
        rows.append({"_checkpoint_update": {"last_start_date": "2026-07-30"},
                     "_empty_marker": True, "_fetch_failed": True})
        audit, saved = _run_source(rows, _conf(enable_user_lookup=False), {})
        self.assertGreater(audit["errors"], 0, "a broken feed reported no error")
        self.assertNotIn("last_start_date", saved,
                         "the window advanced over pages that never arrived")


# ---------------------------------------------------------------------------
# Fetcher-level: the same guarantee, one layer down
# ---------------------------------------------------------------------------

class _Fetcher(BaseFetcher):
    def __init__(self):
        super().__init__("t", "/x/{company_id}")

    def _map_record(self, rec, conf):
        return dict(rec)


class _Resp:
    def __init__(self, body, status=200):
        self._body = body
        self.status_code = status
        self.text = ""
        self.headers = {}

    def json(self):
        return self._body


def _page(n, total=None):
    data = {"data": [{"email": f"a{i}@example.com"} for i in range(n)]}
    if total is not None:
        data["total_data_count"] = total
    return {"is_success": True, "data": data}


def _fetch(pages):
    responses = iter(pages)
    calls = {"n": 0}

    def get(url, headers=None, params=None, timeout=None):
        calls["n"] += 1
        item = next(responses)
        if isinstance(item, Exception):
            raise item
        return _Resp(item)

    conf = {"socradar_company_id": "1", "socradar_api_key": "k",
            # Pin the window instead of deriving it from the lookback. The
            # derived value is "ten hours ago", which lands on today's date
            # after 10:00 UTC and on yesterday's before it, so an assertion
            # written against it passes or fails by the clock rather than by
            # the behaviour it means to describe.
            "initial_start_date": WINDOW_START}
    with mock.patch("sources.base_fetcher.requests.get", side_effect=get), \
         mock.patch("sources.base_fetcher.time.sleep"):
        records = _Fetcher().fetch(conf, {})
    return calls["n"], records


# The window every _fetch call starts from. Fixed, so "did the window move?"
# is answered by comparing against it rather than against the current date.
WINDOW_START = "2026-01-15"


def _today():
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")


class AFeedThatDoesNotSayHowMuchThereIs(unittest.TestCase):
    """Treating a missing count as zero made one full page look like the lot."""

    def test_it_keeps_asking_while_pages_come_back_full(self):
        calls, records = _fetch([_page(100), _page(100), _page(40)])
        got = len([r for r in records if "email" in r])
        self.assertEqual(calls, 3)
        self.assertEqual(got, 240, "pages behind the first were dropped")

    def test_a_short_page_ends_the_window(self):
        _, records = _fetch([_page(100), _page(40)])
        self.assertEqual(records[-1]["_checkpoint_update"]["last_start_date"], _today())

    def test_the_reported_count_is_still_honoured_when_present(self):
        # The live contract: the feed does report the count, and that path must
        # behave exactly as it did before.
        calls, records = _fetch([_page(100, 500)] * 5 + [_page(0, 500)])
        self.assertEqual(calls, 5)
        self.assertEqual(len([r for r in records if "email" in r]), 500)
        self.assertEqual(records[-1]["_checkpoint_update"]["last_start_date"], _today())


class APageThatArrivesEmptyTooEarly(unittest.TestCase):
    """The feed promised more and sent nothing. That page is not consumed."""

    def test_the_window_is_held_rather_than_skipped(self):
        _, records = _fetch([_page(100, 500), _page(0, 500)])
        checkpoint = records[-1]["_checkpoint_update"]
        # Held means the window is exactly where it started, not merely
        # "some date that is not today".
        self.assertEqual(checkpoint["last_start_date"], WINDOW_START,
                         "the window moved even though a page was never read")
        self.assertEqual(checkpoint["last_page"], 1, "the empty page must be re-read")

    def test_it_is_reported_as_a_failure(self):
        _, records = _fetch([_page(100, 500), _page(0, 500)])
        self.assertTrue(records[-1].get("_fetch_failed"))

    def test_a_genuinely_empty_window_still_advances(self):
        _, records = _fetch([_page(0, 0)])
        self.assertEqual(records[-1]["_checkpoint_update"]["last_start_date"], _today())
        self.assertFalse(records[-1].get("_fetch_failed"))


class ARequestThatBrokeAfterTheFirstPage(unittest.TestCase):
    """The flag used to be attached only to runs that returned nothing at all."""

    def test_the_failure_reaches_the_caller(self):
        import requests
        _, records = _fetch([_page(100, 500), requests.RequestException("reset")])
        self.assertTrue(records[-1].get("_fetch_failed"),
                        "a run that lost the feed mid-stream reported nothing")

    def test_the_checkpoint_still_rides_with_it(self):
        import requests
        _, records = _fetch([_page(100, 500), requests.RequestException("reset")])
        self.assertIn("_checkpoint_update", records[-1])
        self.assertEqual(records[-1]["_checkpoint_update"]["last_page"], 1)

    def test_the_records_it_did_get_are_still_returned(self):
        import requests
        _, records = _fetch([_page(100, 500), requests.RequestException("reset")])
        self.assertEqual(len([r for r in records if "email" in r]), 100)


if __name__ == "__main__":
    unittest.main()
