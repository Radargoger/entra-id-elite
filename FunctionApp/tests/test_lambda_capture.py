"""Each planned action must act on the person it was planned for.

The action list is built per employee and invoked a few lines later. If an
action ever bound the loop variable by reference instead of by value, everyone
in the batch would be acted on with the last employee's user id -- sessions
revoked on the wrong account, and nothing in the audit trail to show it.

These tests drive the real import path, so removing the binding would fail
them. The previous version of this file only exercised functools.partial
itself and passed no matter what the repository did.
"""

import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from test_import_path import _ensure_azure_stub  # noqa: E402

_ensure_azure_stub()

import function_app  # noqa: E402
from test_action_gates import _FakeLedger, _conf, _run  # noqa: E402


EMAILS = ["aaa@x.com", "bbb@x.com", "ccc@x.com"]


def _lookup_distinct(email, headers):
    """Give every employee their own directory object id."""
    return {"id": f"id-for-{email}", "accountEnabled": True}, 200


class EachActionActsOnItsOwnEmployee(unittest.TestCase):

    def _employees(self):
        employees = [{"email": e} for e in EMAILS]
        employees[-1]["_checkpoint_update"] = {"last_start_date": "2026-07-27"}
        return employees

    def test_every_revoke_targets_that_employees_own_id(self):
        seen = []
        revoke = mock.Mock(side_effect=lambda uid, headers: seen.append(uid) or True)

        _run(_conf(enable_revoke_session=True), self._employees(), _FakeLedger(),
             lookup=_lookup_distinct, revoke_sessions=revoke)

        self.assertEqual(seen, [f"id-for-{e}" for e in EMAILS])
        self.assertNotEqual(len(set(seen)), 1,
                            "all three must not collapse onto one account")

    def test_two_different_actions_on_one_employee_share_that_id(self):
        revoked, disabled = [], []

        _run(_conf(enable_revoke_session=True, enable_disable_account=True),
             self._employees(), _FakeLedger(), lookup=_lookup_distinct,
             revoke_sessions=mock.Mock(side_effect=lambda uid, h: revoked.append(uid) or True),
             disable_account=mock.Mock(side_effect=lambda uid, h: disabled.append(uid) or True))

        self.assertEqual(revoked, disabled)
        self.assertEqual(len(revoked), 3)

    def test_group_action_carries_the_configured_group(self):
        calls = []

        _run(_conf(enable_add_to_group=True, security_group_id="grp-123"),
             self._employees(), _FakeLedger(), lookup=_lookup_distinct,
             add_to_group=mock.Mock(side_effect=lambda uid, gid, h: calls.append((uid, gid)) or True))

        self.assertEqual(calls, [(f"id-for-{e}", "grp-123") for e in EMAILS])


class PlanModeNamesTheSameActions(unittest.TestCase):
    """What plan mode reports must be what apply mode would do, or the preview
    is not a preview."""

    def test_planned_names_match_the_applied_names(self):
        employees = [{"email": "a@x.com",
                      "_checkpoint_update": {"last_start_date": "2026-07-27"}}]

        _, plan_records, _ = _run(
            _conf(entra_action_mode="plan", enable_revoke_session=True,
                  enable_disable_account=True),
            employees, _FakeLedger(), lookup=_lookup_distinct)

        _, apply_records, _ = _run(
            _conf(entra_action_mode="apply", enable_revoke_session=True,
                  enable_disable_account=True),
            employees, _FakeLedger(), lookup=_lookup_distinct,
            revoke_sessions=mock.Mock(return_value=True),
            disable_account=mock.Mock(return_value=True))

        planned = [a.replace("_planned", "") for a in plan_records[0]["actions_taken"]]
        applied = apply_records[0]["actions_taken"]
        self.assertEqual(planned, applied)


if __name__ == "__main__":
    unittest.main()
