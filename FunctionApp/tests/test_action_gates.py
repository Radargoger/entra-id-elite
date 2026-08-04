"""The gates that stand between a leaked-credential feed and someone's account.

Each test here corresponds to a defect found by adversarial review of the
apply path. They are written so that reverting the fix makes them fail.
"""

import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from test_import_path import _ensure_azure_stub  # noqa: E402

_ensure_azure_stub()

import function_app  # noqa: E402


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


class _FakeLedger:
    """Stands in for the Table Storage ledger, with a pre-seeded history."""

    def __init__(self, already=()):
        self._done = set(already)
        self.recorded = []

    def already_applied(self, email, source, action, window_date):
        return (email, action) in self._done

    def record_applied(self, email, source, action, window_date):
        self.recorded.append((email, action))
        self._done.add((email, action))


def _conf(**over):
    conf = {
        "socradar_company_id": "1", "socradar_api_key": "k",
        "socradar_base_url": "https://example.invalid",
        "company_map_raw": "", "tenant_ids": ["t-a"], "tenant_id": "",
        "client_id": "app-1", "storage_account_name": "sa",
        "enable_user_lookup": True, "verified_domains": [],
        "entra_action_mode": "apply", "entra_max_actions_per_run": 50,
        "enable_revoke_session": False, "enable_add_to_group": False,
        "enable_remove_from_group": False, "enable_password_change": False,
        "enable_disable_account": False, "enable_enable_account": False,
        "enable_confirm_risky": False, "enable_force_mfa_reregistration": False,
        "enable_create_incident": False, "enable_resolve_alarm": False,
        "enable_ropc": False, "security_group_id": "",
        "initial_lookback_minutes": 43200, "initial_start_date": "",
        "max_pages_per_run": 50,
    }
    conf.update(over)
    return conf


def _found(*_a, **_k):
    return {"id": "u-1", "accountEnabled": True}, 200


def _run(conf, employees, ledger, lookup=_found, checkpoint=None, **patches):
    """Drive _process_source over `employees` with a controllable ledger."""
    written = {}

    def capture(_conf, _source, records, **kw):
        written["records"] = list(records)
        return True

    stack = [
        mock.patch.object(function_app.src_botnet, "fetch", return_value=employees),
        mock.patch.object(function_app.cp, "load", return_value=dict(checkpoint or {})),
        mock.patch.object(function_app.law, "write_records", side_effect=capture),
        mock.patch.object(function_app.entra, "lookup_user", side_effect=lookup),
        mock.patch.object(function_app.ledger_mod, "ActionLedger", return_value=ledger),
    ]
    for name, new in patches.items():
        stack.append(mock.patch.object(function_app.entra, name, new))

    with mock.patch.object(function_app.cp, "save") as save:
        for p in stack:
            p.start()
        try:
            result = function_app._process_source(
                "botnet", conf, None, {"t-a": {"Authorization": "x"}},
                deadline=float("inf"), checkpoint_key="botnet:1")
        finally:
            for p in reversed(stack):
                p.stop()
    return result, written.get("records", []), save


class CeilingIsForWorkNotNoOps(unittest.TestCase):
    """The run ceiling limits directory changes. Actions already applied in an
    earlier run are not changes, so they must not consume the budget: otherwise
    a re-read window starves the people who have not been helped yet."""

    def test_a_fresh_record_still_gets_its_action_behind_ten_repeats(self):
        emails = [f"old{i}@x.com" for i in range(10)]
        employees = [{"email": e} for e in emails] + [{"email": "new@x.com"}]
        employees[-1]["_checkpoint_update"] = {"last_start_date": "2026-07-27"}

        ledger = _FakeLedger(already={(e, "revoke_session") for e in emails})
        revoke = mock.Mock(return_value=True)

        conf = _conf(enable_revoke_session=True, entra_max_actions_per_run=10)
        _, records, _ = _run(conf, employees, ledger, revoke_sessions=revoke)

        self.assertEqual(revoke.call_count, 1,
                         "the one person who still needs help must be reached")
        self.assertIn("revoke_session", records[-1]["actions_taken"])
        self.assertNotIn("revoke_session_skipped_cap", records[-1]["actions_taken"])

    def test_repeats_are_reported_as_repeats(self):
        employees = [{"email": "old@x.com", "_checkpoint_update": {"last_start_date": "2026-07-27"}}]
        ledger = _FakeLedger(already={("old@x.com", "revoke_session")})
        revoke = mock.Mock(return_value=True)

        conf = _conf(enable_revoke_session=True)
        _, records, _ = _run(conf, employees, ledger, revoke_sessions=revoke)

        revoke.assert_not_called()
        self.assertIn("revoke_session_skipped_idempotent", records[0]["actions_taken"])


class IncidentsAreNotRaisedTwice(unittest.TestCase):
    def test_second_pass_over_the_same_window_raises_no_new_incident(self):
        employees = [{"email": "a@x.com", "_checkpoint_update": {"last_start_date": "2026-07-27"}}]
        ledger = _FakeLedger(already={("a@x.com", "create_incident")})

        conf = _conf(enable_create_incident=True)
        with mock.patch.object(function_app.sent, "create_incident") as create:
            _, records, _ = _run(conf, employees, ledger)

        create.assert_not_called()
        self.assertIn("create_incident_skipped_idempotent", records[0]["actions_taken"])

    def test_first_pass_raises_one_and_remembers_it(self):
        employees = [{"email": "a@x.com", "_checkpoint_update": {"last_start_date": "2026-07-27"}}]
        ledger = _FakeLedger()

        conf = _conf(enable_create_incident=True)
        with mock.patch.object(function_app.sent, "create_incident", return_value=True) as create:
            _, records, _ = _run(conf, employees, ledger)

        create.assert_called_once()
        self.assertIn(("a@x.com", "create_incident"), ledger.recorded)

    def test_an_incident_that_was_never_raised_is_not_recorded_as_raised(self):
        """Sentinel can refuse the incident — bad config, no token, HTTP 500.
        Marking it done anyway retires it for this window and nobody is ever
        told about the leak."""
        employees = [{"email": "a@x.com", "_checkpoint_update": {"last_start_date": "2026-07-27"}}]
        ledger = _FakeLedger()

        conf = _conf(enable_create_incident=True)
        with mock.patch.object(function_app.sent, "create_incident", return_value=False):
            _, records, _ = _run(conf, employees, ledger)

        self.assertEqual(ledger.recorded, [], "a failure must stay retryable")
        self.assertIn("create_incident_failed", records[0]["actions_taken"])


class AlarmResolutionRespectsTheCeiling(unittest.TestCase):
    def test_alarm_is_not_resolved_past_the_ceiling(self):
        employees = [{"email": "a@x.com", "alarm_id": "77",
                      "_checkpoint_update": {"last_start_date": "2026-07-27"}}]
        ledger = _FakeLedger()

        # One revoke consumes the only slot; the alarm must wait for the next run.
        conf = _conf(enable_revoke_session=True, enable_resolve_alarm=True,
                     entra_max_actions_per_run=1)
        with mock.patch.object(function_app.socradar_api, "resolve_alarm") as resolve:
            _, records, _ = _run(conf, employees, ledger,
                                 revoke_sessions=mock.Mock(return_value=True))

        resolve.assert_not_called()
        self.assertIn("resolve_alarm_skipped_cap", records[0]["actions_taken"])


class ARecordThatRaisedIsNotADoneRecord(unittest.TestCase):
    """A record that threw never reached Log Analytics. Advancing the checkpoint
    past it loses it for good, because the window is never fetched again."""

    @staticmethod
    def _explode(email, headers):
        if email == "boom@x.com":
            raise RuntimeError("table storage unavailable")
        return _found()

    @staticmethod
    def _employees():
        return [{"email": "boom@x.com"},
                {"email": "ok@x.com",
                 "_checkpoint_update": {"last_start_date": "2026-07-27"}}]

    def test_the_position_is_kept_and_the_hold_is_counted(self):
        result, _, save = _run(_conf(), self._employees(), _FakeLedger(),
                               lookup=self._explode,
                               checkpoint={"last_start_date": "2026-06-01"})

        self.assertGreater(result["errors"], 0)
        saved = save.call_args[0][3]
        self.assertEqual(saved.get("last_start_date"), "2026-06-01",
                         "the window still holds a record nobody stored")
        self.assertEqual(saved.get("consecutive_holds"), 1)

    def test_a_first_run_does_not_advance_past_the_lost_record(self):
        # With no prior checkpoint there is no position to rewrite, so the
        # guarantee is simply that the new one is never written.
        _, _, save = _run(_conf(), self._employees(), _FakeLedger(),
                          lookup=self._explode)

        _assert_window_not_written_off(self, save)


class PlaintextDoesNotOutliveTheLookup(unittest.TestCase):
    """ROPC is the only consumer of the plaintext password. Every path that
    skips ROPC must still leave the password behind."""

    def _record_for(self, lookup):
        employees = [{
            "email": "a@x.com",
            "sanitized": {"is_plaintext": True, "_raw": "SuperSecret123", "masked": "S***3"},
            "_checkpoint_update": {"last_start_date": "2026-07-27"},
        }]
        _, records, _ = _run(_conf(), employees, _FakeLedger(), lookup=lookup)
        return records[0]

    def test_not_found_record_carries_no_password(self):
        rec = self._record_for(lambda *a, **k: (None, 404))
        self.assertNotIn("_raw", rec.get("sanitized", {}))

    def test_lookup_failure_record_carries_no_password(self):
        rec = self._record_for(lambda *a, **k: (None, 503))
        self.assertNotIn("_raw", rec.get("sanitized", {}))

    def test_permission_denied_record_carries_no_password(self):
        rec = self._record_for(lambda *a, **k: (None, 403))
        self.assertNotIn("_raw", rec.get("sanitized", {}))

    def test_found_record_carries_no_password_either(self):
        rec = self._record_for(_found)
        self.assertNotIn("_raw", rec.get("sanitized", {}))


class ApplyModeWillNotRunWithoutItsLedger(unittest.TestCase):
    """Falling back to an in-memory ledger would silently switch idempotency
    off, and the run would act on people it had already acted on."""

    def test_an_unreachable_ledger_stops_the_source(self):
        employees = [{"email": "a@x.com", "_checkpoint_update": {}}]

        with mock.patch.object(function_app.src_botnet, "fetch", return_value=employees), \
             mock.patch.object(function_app.cp, "load", return_value={}), \
             mock.patch.object(function_app.cp, "save"), \
             mock.patch.object(function_app.law, "write_records", return_value=True), \
             mock.patch.object(function_app.ledger_mod, "ActionLedger",
                               side_effect=RuntimeError("403 from table service")):
            with self.assertRaises(RuntimeError) as caught:
                function_app._process_source(
                    "botnet", _conf(enable_revoke_session=True), None,
                    {"t-a": {"Authorization": "x"}},
                    deadline=float("inf"), checkpoint_key="botnet:1")

        self.assertIn("ledger", str(caught.exception).lower())

    def test_plan_mode_needs_no_table(self):
        employees = [{"email": "a@x.com", "_checkpoint_update": {"last_start_date": "2026-07-27"}}]
        revoke = mock.Mock()

        with mock.patch.object(function_app.src_botnet, "fetch", return_value=employees), \
             mock.patch.object(function_app.cp, "load", return_value={}), \
             mock.patch.object(function_app.cp, "save"), \
             mock.patch.object(function_app.law, "write_records", return_value=True), \
             mock.patch.object(function_app.entra, "lookup_user", side_effect=_found), \
             mock.patch.object(function_app.entra, "revoke_sessions", revoke), \
             mock.patch.object(function_app.ledger_mod, "ActionLedger",
                               side_effect=AssertionError("plan mode must not touch the table")):
            result = function_app._process_source(
                "botnet", _conf(entra_action_mode="plan", enable_revoke_session=True),
                None, {"t-a": {"Authorization": "x"}},
                deadline=float("inf"), checkpoint_key="botnet:1")

        revoke.assert_not_called()
        self.assertEqual(result["actions"], 1)


if __name__ == "__main__":
    unittest.main()
