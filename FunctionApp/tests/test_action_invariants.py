"""Every directory change goes through the same gates, including the next one.

The tests around this codebase pin behaviour example by example: this response,
that ledger entry. That leaves a gap. A tenth action added tomorrow can reach
Microsoft Graph without passing the run ceiling, the idempotency ledger or the
audit trail, and every existing test stays green.

So this file asserts the property rather than the instances, and forces a
decision about any function added later.
"""

import inspect
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from test_import_path import _ensure_azure_stub  # noqa: E402

_ensure_azure_stub()

import function_app  # noqa: E402
from actions import entra_id as entra  # noqa: E402
from actions.action_ledger import InMemoryActionLedger  # noqa: E402


# Functions that change something in the customer's directory. Reaching Graph
# with anything other than GET puts a name here.
MUTATIONS = {
    "revoke_sessions",
    "add_to_group",
    "remove_from_group",
    "disable_account",
    "enable_account",
    "force_password_change",
    "confirm_compromised",
    "force_mfa_reregistration",
}

# Functions that only read, or that never touch a directory object.
# validate_password_ropc does POST, but to the login endpoint rather than
# Graph: it attempts a sign-in and changes nothing. It is still not free of
# consequence, since repeated failures feed Entra's smart lockout counter,
# which is why the deployment leaves it off.
NON_MUTATIONS = {
    "get_graph_token",
    "lookup_user",
    "validate_password_ropc",
}


def _public_functions():
    """Public functions defined in entra_id itself.

    inspect also reports names imported into the module (quote from urllib),
    so the module check is what makes this an inventory rather than a guess.
    """
    return {
        name for name, fn in inspect.getmembers(entra, inspect.isfunction)
        if fn.__module__ == entra.__name__ and not name.startswith("_")
    }


class TheInventoryIsComplete(unittest.TestCase):
    """A new function in entra_id must be classified before it can ship."""

    def test_every_public_function_is_classified(self):
        unclassified = _public_functions() - MUTATIONS - NON_MUTATIONS
        self.assertEqual(
            unclassified, set(),
            "new function(s) in actions/entra_id.py: decide whether each one "
            "changes the directory, add it to MUTATIONS or NON_MUTATIONS, and "
            "if it mutates make sure its call site passes the gates below")

    def test_the_lists_describe_functions_that_exist(self):
        missing = (MUTATIONS | NON_MUTATIONS) - _public_functions()
        self.assertEqual(missing, set(),
                         "these names no longer exist; the lists are stale")

    def test_nothing_is_in_both_lists(self):
        self.assertEqual(MUTATIONS & NON_MUTATIONS, set())


def _conf(**over):
    conf = {
        "socradar_company_id": "1", "socradar_api_key": "k",
        "socradar_base_url": "https://example.invalid",
        "dcr_immutable_id": "dcr-1", "dcr_endpoint": "https://x.invalid",
        "company_map_raw": "", "tenant_ids": ["t-a"], "tenant_id": "",
        "client_id": "app-1", "storage_account_name": "sa",
        "enable_user_lookup": True, "verified_domains": [],
        "entra_action_mode": "apply", "entra_max_actions_per_run": 50,
        "security_group_id": "grp-1", "enable_ropc": False,
        "enable_create_incident": False, "enable_resolve_alarm": False,
        "initial_lookback_minutes": 43200, "initial_start_date": "",
        "max_pages_per_run": 50,
    }
    # Every response this deployment can arm, armed.
    for flag in ("enable_revoke_session", "enable_add_to_group",
                 "enable_remove_from_group", "enable_disable_account",
                 "enable_enable_account", "enable_password_change",
                 "enable_confirm_risky", "enable_force_mfa_reregistration"):
        conf[flag] = True
    conf.update(over)
    return conf


def _run_with_tripwires(conf, ledger=None):
    """Drive the import path with every mutation replaced by a recorder.

    The tripwire records instead of raising on purpose. _process_source wraps
    each record in a broad `except Exception`, so a raising tripwire would be
    swallowed and the test would pass while proving nothing.
    """
    fired = []

    def tripwire(name):
        def _call(*a, **k):
            fired.append(name)
            # force_mfa_reregistration answers with a dict, not a bool.
            if name == "force_mfa_reregistration":
                return {"methods_deleted": 1, "methods_skipped": 0,
                        "permission_denied": False, "errors": []}
            return True
        return _call

    employees = [{"email": "a@x.com",
                  "_checkpoint_update": {"last_start_date": "2026-07-27"}}]
    written = {}

    def capture(_c, _s, records, **kw):
        written["records"] = list(records)
        return True

    patches = [mock.patch.object(entra, name, tripwire(name)) for name in sorted(MUTATIONS)]
    patches += [
        mock.patch.object(function_app.src_botnet, "fetch", return_value=employees),
        mock.patch.object(function_app.cp, "load", return_value={}),
        mock.patch.object(function_app.cp, "save"),
        mock.patch.object(function_app.law, "write_records", side_effect=capture),
        mock.patch.object(function_app.entra, "lookup_user",
                          return_value=({"id": "u1", "accountEnabled": True}, 200)),
        mock.patch.object(function_app.ledger_mod, "ActionLedger",
                          return_value=ledger or InMemoryActionLedger()),
    ]
    for p in patches:
        p.start()
    try:
        result = function_app._process_source(
            "botnet", conf, None, {"t-a": {"Authorization": "x"}},
            deadline=float("inf"), checkpoint_key="botnet:1")
    finally:
        for p in reversed(patches):
            p.stop()

    recs = written.get("records") or []
    return fired, (recs[0].get("actions_taken") if recs else None), result


class PlanModeTouchesNothing(unittest.TestCase):
    def test_no_mutation_runs_and_every_one_is_reported_as_planned(self):
        fired, taken, _ = _run_with_tripwires(_conf(entra_action_mode="plan"))
        self.assertEqual(fired, [], "plan mode reached the directory")
        self.assertTrue(taken, "the record never reached Log Analytics")
        self.assertTrue(all(a.endswith("_planned") for a in taken),
                        f"plan mode reported something other than a plan: {taken}")


class WorkAlreadyDoneIsNotRepeated(unittest.TestCase):
    def test_a_full_ledger_stops_every_mutation(self):
        class _AllDone:
            def already_applied(self, *a):
                return True

            def record_applied(self, *a):
                raise AssertionError("recorded an action it did not take")

        fired, taken, _ = _run_with_tripwires(_conf(), ledger=_AllDone())
        self.assertEqual(fired, [], "acted on work the ledger said was done")
        self.assertTrue(all("_skipped_idempotent" in a for a in taken),
                        f"unexpected outcome: {taken}")


class TheCeilingHoldsTheDirectory(unittest.TestCase):
    def test_a_ceiling_of_zero_lets_nothing_through(self):
        fired, _, result = _run_with_tripwires(_conf(entra_max_actions_per_run=0))
        reached = set(fired) & MUTATIONS
        self.assertEqual(reached, set(),
                         f"these ran with no budget left: {sorted(reached)}")
        self.assertTrue(result["capped"], "a blocked run did not report itself capped")


class SuccessIsRecorded(unittest.TestCase):
    """The ledger is what stops a re-read window repeating itself, so an action
    that ran must be in it, and one that failed must not."""

    def test_a_successful_run_is_written_to_the_ledger(self):
        recorded = []

        class _Recording(InMemoryActionLedger):
            def record_applied(self, email, source, action, window_date):
                recorded.append(action)
                super().record_applied(email, source, action, window_date)

        fired, taken, _ = _run_with_tripwires(_conf(), ledger=_Recording())
        self.assertTrue(fired, "nothing ran, so this proves nothing")

        applied = [a for a in taken if not a.endswith(
            ("_planned", "_skipped_idempotent", "_skipped_cap", "_failed",
             "_no_methods", "_no_permission"))]
        self.assertTrue(applied, f"no action reported success: {taken}")
        self.assertEqual(sorted(set(applied)), sorted(set(recorded)),
                         "an action ran but was never written to the ledger, so "
                         "the next pass over this window would repeat it")


if __name__ == "__main__":
    unittest.main()
