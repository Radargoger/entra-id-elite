"""A failure must never be filed as "nothing was found".

Each of these was a real silent false negative: a broken lookup, a failed LAW
write, or a failed fetch would read as a clean, empty run — and the checkpoint
moved past the window, so it was never read again.
"""

import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from test_import_path import _ensure_azure_stub  # noqa: E402

_ensure_azure_stub()

import function_app  # noqa: E402
from sources import botnet, pii, vip  # noqa: E402
from utils import sanitize  # noqa: E402


def _assert_window_not_written_off(test, save):
    """A held window means the finished-window marker was never written.

    "save was never called" used to state that, and no longer does: a held run
    now also persists consecutive_holds, so that a run holding on its very first
    pass can still arm the abandon escape. What has to stay true is narrower and
    is what these tests were always about — nothing recorded the window as done,
    so the next run reads it again.

    These callers all start from an empty checkpoint, so the guarantee takes its
    strongest form: no position may be written at all. Naming an expected date
    here instead would pass silently the day a fixture used a different one.
    """
    for call in save.call_args_list:
        test.assertNotIn(
            "last_start_date", call[0][3],
            "the window was written off despite a failure",
        )


def _conf(**over):
    conf = {
        "storage_account_name": "sa",
        "socradar_api_key": "k", "socradar_company_id": "1234567",
        "socradar_base_url": "https://example.invalid",
        "enable_user_lookup": True, "verified_domains": [],
        "enable_create_incident": False, "enable_resolve_alarm": False,
        "enable_ropc": False, "entra_action_mode": "plan",
        "entra_max_actions_per_run": 50, "security_group_id": "",
        "enable_revoke_session": False, "enable_add_to_group": False,
        "enable_remove_from_group": False, "enable_password_change": False,
        "enable_disable_account": False, "enable_enable_account": False,
        "enable_confirm_risky": False, "enable_force_mfa_reregistration": False,
        "initial_lookback_minutes": 43200, "initial_start_date": "",
        "max_pages_per_run": 50,
    }
    conf.update(over)
    return conf


def _run(lookup_result, law_ok=True, records=2):
    employees = [{"email": f"u{i}@x.com"} for i in range(records)]
    employees[-1]["_checkpoint_update"] = {"last_start_date": "2026-07-27"}

    with mock.patch.object(function_app.src_botnet, "fetch", return_value=employees), \
         mock.patch.object(function_app.cp, "load", return_value={}), \
         mock.patch.object(function_app.cp, "save") as save, \
         mock.patch.object(function_app.law, "write_records", return_value=law_ok), \
         mock.patch.object(function_app.entra, "lookup_user", return_value=lookup_result):
        result = function_app._process_source(
            "botnet", _conf(), None, {"t-a": {"h": "x"}},
            deadline=float("inf"), checkpoint_key="botnet:1234567")
    return result, save


class LookupFailureTest(unittest.TestCase):
    def test_server_error_is_not_reported_as_not_found(self):
        result, save = _run((None, 503))
        self.assertEqual(result["not_found"], 0, "a 503 says nothing about the person")
        self.assertGreater(result["errors"], 0)
        _assert_window_not_written_off(self, save)  # window must be read again

    def test_network_error_is_not_reported_as_not_found(self):
        result, save = _run((None, 0))
        self.assertEqual(result["not_found"], 0)
        self.assertGreater(result["errors"], 0)
        _assert_window_not_written_off(self, save)

    def test_a_real_404_still_counts_as_not_found(self):
        result, save = _run((None, 404))
        self.assertEqual(result["not_found"], 2)
        self.assertEqual(result["errors"], 0)
        save.assert_called_once()  # nothing failed, so the window is done

    def test_found_user_advances_the_checkpoint(self):
        result, save = _run(({"id": "u1", "accountEnabled": True}, 200))
        self.assertEqual(result["found"], 2)
        save.assert_called_once()


class LawWriteFailureTest(unittest.TestCase):
    def test_failed_law_write_holds_the_checkpoint(self):
        """Records that never reached Log Analytics are not 'handled'."""
        result, save = _run((None, 404), law_ok=False)
        self.assertGreater(result["errors"], 0)
        _assert_window_not_written_off(self, save)


class FetchFailureFlagTest(unittest.TestCase):
    """All three feeds must mark a broken fetch, not just botnet."""

    def _broken_fetch(self, module):
        with mock.patch.object(module.requests, "get",
                               side_effect=module.requests.RequestException("boom")):
            return module.fetch(_conf(), {}, deadline=None)

    def test_botnet_marks_a_broken_fetch(self):
        recs = self._broken_fetch(botnet)
        self.assertTrue(recs[0].get("_fetch_failed"))

    def test_pii_marks_a_broken_fetch(self):
        recs = self._broken_fetch(pii)
        self.assertTrue(recs[0].get("_fetch_failed"))

    def test_vip_marks_a_broken_fetch(self):
        recs = self._broken_fetch(vip)
        self.assertTrue(recs[0].get("_fetch_failed"))


class EmptyFeedTest(unittest.TestCase):
    """An empty window is a finished window, not a failure."""

    class _Empty:
        status_code = 200

        def json(self):
            return {"is_success": True,
                    "data": {"total_pages": 1, "total_data_count": 0, "data": []}}

    def test_empty_feed_is_not_an_error(self):
        with mock.patch.object(botnet.requests, "get", return_value=self._Empty()):
            recs = botnet.fetch(_conf(), {}, deadline=None)
        self.assertFalse(recs[0].get("_fetch_failed"),
                         "no leaks in the window is not a broken fetch")

    def test_empty_feed_moves_the_window_on(self):
        with mock.patch.object(botnet.requests, "get", return_value=self._Empty()):
            recs = botnet.fetch(_conf(), {}, deadline=None)
        chk = recs[0]["_checkpoint_update"]
        self.assertEqual(chk["last_page"], 0,
                         "an exhausted window must not be re-queried forever")


class PermissionDeniedTest(unittest.TestCase):
    def test_403_also_holds_the_checkpoint(self):
        """A tenant awaiting admin consent answers 403 for everyone. Writing that
        window off would skip the whole backlog once consent lands."""
        result, save = _run((None, 403))
        self.assertGreater(result["errors"], 0)
        _assert_window_not_written_off(self, save)


class StuckWindowTest(unittest.TestCase):
    """Holding forever is its own failure: nothing behind the window is read."""

    def _run_with_holds(self, holds):
        employees = [{"email": "u@x.com", "_checkpoint_update": {"last_start_date": "2026-07-27"}}]
        with mock.patch.object(function_app.src_botnet, "fetch", return_value=employees), \
             mock.patch.object(function_app.cp, "load",
                               return_value={"last_start_date": "2026-06-01",
                                             "consecutive_holds": holds}), \
             mock.patch.object(function_app.cp, "save") as save, \
             mock.patch.object(function_app.law, "write_records", return_value=True), \
             mock.patch.object(function_app.law, "write_lifecycle_event") as life, \
             mock.patch.object(function_app.entra, "lookup_user", return_value=(None, 503)):
            function_app._process_source(
                "botnet", _conf(), None, {"t-a": {"h": "x"}},
                deadline=float("inf"), checkpoint_key="botnet:1234567")
        return save, life

    def test_repeated_failures_count_up(self):
        save, life = self._run_with_holds(1)
        saved = save.call_args[0][3]
        self.assertEqual(saved["consecutive_holds"], 2)
        self.assertEqual(saved["last_start_date"], "2026-06-01", "position is kept")
        life.assert_not_called()

    def test_a_window_is_finally_released(self):
        save, life = self._run_with_holds(function_app.MAX_CONSECUTIVE_HOLDS - 1)
        saved = save.call_args[0][3]
        self.assertEqual(saved["last_start_date"], "2026-07-27", "the feed moves on")
        self.assertEqual(saved["consecutive_holds"], 0)
        life.assert_called_once()  # and it is reported, not silent


class EmailInUrlTest(unittest.TestCase):
    """The address comes from a third-party feed and lands in a URL path."""

    def _asked_url(self, email):
        seen = {}

        class _R:
            status_code = 404

            def json(self):
                return {}

        def fake_request(method, url, headers=None, **kw):
            seen["url"] = url
            return _R()

        from actions import entra_id
        with mock.patch.object(entra_id.requests, "request", side_effect=fake_request):
            entra_id.lookup_user(email, {"Authorization": "x"})
        return seen["url"]

    def test_fragment_cannot_truncate_the_request(self):
        url = self._asked_url("user_contoso.com#EXT#@t.onmicrosoft.com")
        self.assertNotIn("#", url, "a '#' would cut the address short at the server")
        self.assertIn("EXT", url)

    def test_query_characters_cannot_escape_the_path(self):
        # The lookup now carries a $select of its own, so "no '?' anywhere" is
        # no longer the invariant — "the address cannot contribute one" is. An
        # unescaped '?' in the address would start the query string early and
        # let a feed value choose which properties Graph returns.
        from actions import entra_id

        url = self._asked_url("a?$select=id@x.com")
        path, _, query = url.partition("?")
        self.assertNotIn("?", path, "the address opened the query string")
        self.assertEqual(url.count("?"), 1, "more than one query string")
        self.assertEqual(query, f"$select={entra_id.LOOKUP_SELECT}",
                         "the query is not the one the code intended")

    def test_a_plain_address_is_left_readable(self):
        url = self._asked_url("ahmet@contoso.com")
        path = url.partition("?")[0]
        self.assertTrue(path.endswith("/users/ahmet@contoso.com"))


class PasswordMaskingTest(unittest.TestCase):
    def test_a_password_containing_stars_is_never_stored_as_is(self):
        """'Yaz**2026!' is a real password, not a masked one."""
        out = sanitize.sanitize_password("Yaz**2026!")
        self.assertNotEqual(out["masked"], "Yaz**2026!")
        self.assertTrue(out["is_plaintext"])
        self.assertNotIn("2026", out["masked"])

    def test_a_genuinely_masked_value_is_recognised(self):
        out = sanitize.sanitize_password("a******3")
        self.assertFalse(out["is_plaintext"])

    def test_masked_output_never_leaks_the_middle(self):
        out = sanitize.sanitize_password("SuperSecret123")
        self.assertEqual(out["masked"], "S***3")

    def test_the_credential_is_recorded_as_the_feed_delivered_it(self):
        """Masked or clear is SOCRadar's per-company setting, decided upstream.
        The record must agree with the source it came from."""
        out = sanitize.sanitize_password("Yaz**2026!")
        fields = sanitize.build_law_password_fields(out)
        self.assertEqual(fields["password"], "Yaz**2026!")

    def test_the_masked_column_still_hides_the_middle(self):
        """Dashboards read password_masked, so it stays safe either way."""
        out = sanitize.sanitize_password("Yaz**2026!")
        fields = sanitize.build_law_password_fields(out)
        self.assertNotIn("2026", fields["password_masked"])


class RopcRawCleanupTest(unittest.TestCase):
    """_raw plaintext password must not linger in emp after ROPC validation."""

    def _run_ropc(self, ropc_return="valid"):
        """Run a single employee through _process_source with ROPC enabled."""
        employees = [
            {
                "email": "leaked@x.com",
                "sanitized": {"is_plaintext": True, "_raw": "SuperSecret123"},
                "_checkpoint_update": {"last_start_date": "2026-07-27"},
            }
        ]
        written = {}

        def capture_write(conf, source_name, records, **kw):
            written["records"] = list(records)
            return True

        with mock.patch.object(function_app.src_botnet, "fetch", return_value=employees), \
             mock.patch.object(function_app.cp, "load", return_value={}), \
             mock.patch.object(function_app.cp, "save"), \
             mock.patch.object(function_app.law, "write_records", side_effect=capture_write), \
             mock.patch.object(function_app.entra, "lookup_user",
                               return_value=({"id": "u1", "accountEnabled": True}, 200)), \
             mock.patch.object(function_app.entra, "validate_password_ropc",
                               return_value=ropc_return) as ropc_mock:
            result = function_app._process_source(
                "botnet",
                _conf(enable_ropc=True, client_id="test-client"),
                None,
                {"t-a": {"h": "x"}},
                deadline=float("inf"),
                checkpoint_key="botnet:1234567",
            )
        return result, written, ropc_mock

    def test_raw_removed_after_ropc_valid(self):
        result, written, ropc_mock = self._run_ropc("valid")
        ropc_mock.assert_called_once()
        for rec in written["records"]:
            san = rec.get("sanitized") or {}
            self.assertNotIn("_raw", san,
                             "_raw plaintext password must not survive past the ROPC block")

    def test_raw_removed_after_ropc_invalid(self):
        result, written, ropc_mock = self._run_ropc("invalid")
        ropc_mock.assert_called_once()
        for rec in written["records"]:
            san = rec.get("sanitized") or {}
            self.assertNotIn("_raw", san)

    def test_ropc_result_still_applied(self):
        result, written, _ = self._run_ropc("valid")
        statuses = [r.get("entra_status") for r in written["records"]]
        self.assertIn("compromised", statuses,
                      "ROPC valid → entra_status must be 'compromised'")

    def test_ropc_invalid_sets_medium_severity(self):
        result, written, _ = self._run_ropc("invalid")
        severities = [r.get("severity") for r in written["records"]]
        self.assertIn("MEDIUM", severities)


if __name__ == "__main__":
    unittest.main()
