"""Idempotency ledger: duplicate actions must not re-apply (code-review B1).

The InMemoryActionLedger is tested directly; the integration test uses mocks
to verify that a second apply-mode run with the same employees skips already-
applied actions, and that plan-mode runs never record to the ledger.
"""

import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from test_import_path import _ensure_azure_stub  # noqa: E402

_ensure_azure_stub()

from actions.action_ledger import InMemoryActionLedger, _row_key  # noqa: E402
import function_app  # noqa: E402


class InMemoryLedgerTest(unittest.TestCase):
    """Direct tests for the InMemoryActionLedger."""

    def test_new_entry_returns_false(self):
        ledger = InMemoryActionLedger()
        self.assertFalse(
            ledger.already_applied("a@x.com", "botnet", "revoke_session", "2026-07-27"))

    def test_recorded_entry_returns_true(self):
        ledger = InMemoryActionLedger()
        ledger.record_applied("a@x.com", "botnet", "revoke_session", "2026-07-27")
        self.assertTrue(
            ledger.already_applied("a@x.com", "botnet", "revoke_session", "2026-07-27"))

    def test_different_action_returns_false(self):
        ledger = InMemoryActionLedger()
        ledger.record_applied("a@x.com", "botnet", "revoke_session", "2026-07-27")
        self.assertFalse(
            ledger.already_applied("a@x.com", "botnet", "force_password_change", "2026-07-27"))

    def test_different_email_returns_false(self):
        ledger = InMemoryActionLedger()
        ledger.record_applied("a@x.com", "botnet", "revoke_session", "2026-07-27")
        self.assertFalse(
            ledger.already_applied("b@x.com", "botnet", "revoke_session", "2026-07-27"))

    def test_different_window_returns_false(self):
        ledger = InMemoryActionLedger()
        ledger.record_applied("a@x.com", "botnet", "revoke_session", "2026-07-27")
        self.assertFalse(
            ledger.already_applied("a@x.com", "botnet", "revoke_session", "2026-07-28"))

    def test_email_is_case_insensitive(self):
        ledger = InMemoryActionLedger()
        ledger.record_applied("A@X.COM", "botnet", "revoke_session", "2026-07-27")
        self.assertTrue(
            ledger.already_applied("a@x.com", "botnet", "revoke_session", "2026-07-27"))


class RowKeyPrivacyTest(unittest.TestCase):
    """The row key must not leak the raw email."""

    def test_row_key_is_a_hex_digest(self):
        rk = _row_key("a@x.com", "revoke_session", "2026-07-27")
        self.assertEqual(len(rk), 64)
        int(rk, 16)  # would raise if not hex


def _conf(**over):
    conf = {
        "storage_account_name": "sa",
        "socradar_api_key": "k", "socradar_company_id": "330",
        "socradar_base_url": "https://example.invalid",
        "enable_user_lookup": True, "verified_domains": [],
        "enable_create_incident": False, "enable_resolve_alarm": False,
        "enable_ropc": False, "entra_action_mode": "apply",
        "entra_max_actions_per_run": 50, "security_group_id": "",
        "enable_revoke_session": True, "enable_add_to_group": False,
        "enable_remove_from_group": False, "enable_password_change": True,
        "enable_disable_account": False, "enable_enable_account": False,
        "enable_confirm_risky": False, "enable_force_mfa_reregistration": False,
        "initial_lookback_minutes": 43200, "initial_start_date": "2026-07-27",
        "max_pages_per_run": 50,
    }
    conf.update(over)
    return conf


def _employees():
    return [
        {"email": "alice@x.com"},
        {"email": "bob@x.com",
         "_checkpoint_update": {"last_start_date": "2026-07-27"}},
    ]


def _run_process_source(conf, already_applied_emails=None):
    """Run _process_source in apply mode. Returns (result, ledger_instance).

    `already_applied_emails` is a set of emails whose actions should already
    be recorded in the ledger (simulates a previous run).
    """
    already_applied_emails = already_applied_emails or set()

    # Pre-seed the in-memory ledger to simulate a previous run's recordings.
    ledger = InMemoryActionLedger()
    for email in already_applied_emails:
        for action in ("revoke_session", "force_password_change"):
            ledger.record_applied(email, "botnet", action, "2026-07-27")

    with mock.patch.object(function_app.src_botnet, "fetch",
                           return_value=_employees()), \
         mock.patch.object(function_app.cp, "load", return_value={}), \
         mock.patch.object(function_app.cp, "save"), \
         mock.patch.object(function_app.law, "write_records", return_value=True), \
         mock.patch.object(function_app.entra, "lookup_user",
                           return_value=({"id": "uid", "accountEnabled": True}, 200)), \
         mock.patch.object(function_app.entra, "revoke_sessions", return_value=True) as revoke, \
         mock.patch.object(function_app.entra, "force_password_change", return_value=True) as pw_change, \
         mock.patch.object(function_app.ledger_mod, "ActionLedger", return_value=ledger), \
         mock.patch.object(function_app.ledger_mod, "InMemoryActionLedger", return_value=ledger):
        result = function_app._process_source(
            "botnet", conf, None, {"t-a": {"h": "x"}},
            deadline=float("inf"), checkpoint_key="botnet:330")
    return result, revoke, pw_change


class IdempotentApplyTest(unittest.TestCase):
    """A second apply-mode run with the same employees must skip already-applied."""

    def test_first_run_applies_actions(self):
        result, revoke, pw_change = _run_process_source(_conf())
        # Both employees should have actions applied
        self.assertEqual(revoke.call_count, 2)
        self.assertEqual(pw_change.call_count, 2)

    def test_second_run_skips_already_applied(self):
        result, revoke, pw_change = _run_process_source(
            _conf(), already_applied_emails={"alice@x.com", "bob@x.com"})
        # Both already applied — no new calls
        self.assertEqual(revoke.call_count, 0)
        self.assertEqual(pw_change.call_count, 0)

    def test_partial_overlap_applies_only_new(self):
        result, revoke, pw_change = _run_process_source(
            _conf(), already_applied_emails={"alice@x.com"})
        # alice skipped, bob applied
        self.assertEqual(revoke.call_count, 1)
        self.assertEqual(pw_change.call_count, 1)


class PlanModeNoRecordTest(unittest.TestCase):
    """Plan-mode runs must not record to the ledger (they mutate nothing)."""

    def test_plan_mode_does_not_call_record(self):
        ledger = InMemoryActionLedger()
        with mock.patch.object(function_app.src_botnet, "fetch",
                               return_value=_employees()), \
             mock.patch.object(function_app.cp, "load", return_value={}), \
             mock.patch.object(function_app.cp, "save"), \
             mock.patch.object(function_app.law, "write_records", return_value=True), \
             mock.patch.object(function_app.entra, "lookup_user",
                               return_value=({"id": "uid", "accountEnabled": True}, 200)), \
             mock.patch.object(function_app.ledger_mod, "InMemoryActionLedger",
                               return_value=ledger):
            result = function_app._process_source(
                "botnet", _conf(entra_action_mode="plan"), None,
                {"t-a": {"h": "x"}},
                deadline=float("inf"), checkpoint_key="botnet:330")
        # Plan mode: no actions should be recorded
        self.assertEqual(len(ledger._seen), 0,
                         "plan-mode must not record to the ledger")
        # But actions should be planned
        self.assertGreater(result["actions"], 0)


if __name__ == "__main__":
    unittest.main()
