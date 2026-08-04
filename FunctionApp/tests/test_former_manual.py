"""Unit tests for the apply_manual + reconcile-union interaction.

The critical scenario: a manually added former entry must NOT be deleted by the
timer reconcile even when the formula does not want it (the manual store union).
Azure is never contacted, everything is fake/mock.

Run with: python3 tests/test_former_manual.py  (from the FunctionApp root)
"""
import os
import sys
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# stub out the azure imports
azure_pkg = types.ModuleType("azure")
tables_mod = types.ModuleType("azure.data.tables")
tables_mod.TableServiceClient = object
tables_mod.TableEntity = dict
core_mod = types.ModuleType("azure.core.exceptions")
core_mod.ResourceNotFoundError = type("ResourceNotFoundError", (Exception,), {})
core_mod.ResourceExistsError = type("ResourceExistsError", (Exception,), {})
sys.modules.setdefault("azure", azure_pkg)
sys.modules["azure.data.tables"] = tables_mod
sys.modules["azure.core.exceptions"] = core_mod

from actions.former_manual import apply_manual


class FakeStore:
    def __init__(self):
        self.data = set()

    def get_set(self):
        return set(self.data)

    def add(self, emails):
        self.data |= set(emails)
        return len(emails)

    def remove(self, emails):
        n = len(self.data & set(emails))
        self.data -= set(emails)
        return n


class FakeClient:
    """Simulation of the SOCRadar list (same semantics as the mock client)."""

    def __init__(self, push_fails=False):
        self.listed = set()
        self.add_calls = []
        self.push_fails = push_fails  # simulates a wrong actor email

    def get_list(self):
        return set(self.listed)

    def add(self, emails, source):
        self.add_calls.append((list(emails), source))
        if self.push_fails:
            return 0
        self.listed |= set(emails)
        return len(emails)

    def remove(self, emails):
        n = len(self.listed & set(emails))
        self.listed -= set(emails)
        return n


def reconcile(formula_desired, store, client):
    """A copy of the core diff logic in function_app.former_employee_sync:
    desired = formula ∪ manual; the add/remove diff is applied."""
    desired = set(formula_desired) | store.get_set()
    current = client.get_list()
    client.add(sorted(desired - current), source="elite-sync")
    client.remove(sorted(current - desired))
    return desired


class TestApplyManual(unittest.TestCase):
    def setUp(self):
        self.store = FakeStore()
        self.client = FakeClient()

    def test_add_persists_and_pushes(self):
        r = apply_manual("add", ["Amy@X.com", "amy@x.com", "not-an-email"], self.store, self.client)
        self.assertEqual(r["accepted"], ["amy@x.com"])  # lowercase + dedup
        self.assertEqual(r["invalid"], ["not-an-email"])
        self.assertEqual(self.store.data, {"amy@x.com"})
        self.assertEqual(self.client.listed, {"amy@x.com"})
        self.assertEqual(self.client.add_calls[0][1], "manual")  # source tag

    def test_manual_entry_survives_reconcile(self):
        # The analyst added it by hand; the formula does NOT want this email
        apply_manual("add", ["leaver@corp.com"], self.store, self.client)
        # Timer tick: the formula wants an empty set
        reconcile(set(), self.store, self.client)
        # NO M-CLOBBER: the manual entry stays in the list
        self.assertIn("leaver@corp.com", self.client.get_list())

    def test_without_store_union_would_clobber(self):
        # Contrast test: without the union it would be deleted (proof of the design rationale)
        self.client.add(["leaver@corp.com"], source="manual")
        desired = set()  # the formula does not want it, and there is NO manual union
        current = self.client.get_list()
        self.client.remove(sorted(current - desired))
        self.assertNotIn("leaver@corp.com", self.client.get_list())

    def test_manual_remove_then_formula_readds(self):
        # The formula wants someone as former, the analyst removed them by hand
        # -> the next tick adds them back
        formula = {"departed@corp.com"}
        reconcile(formula, self.store, self.client)
        apply_manual("remove", ["departed@corp.com"], self.store, self.client)
        self.assertNotIn("departed@corp.com", self.client.get_list())
        reconcile(formula, self.store, self.client)  # policy wins
        self.assertIn("departed@corp.com", self.client.get_list())

    def test_remove_clears_store_and_list(self):
        apply_manual("add", ["a@x.com", "b@x.com"], self.store, self.client)
        r = apply_manual("remove", ["a@x.com"], self.store, self.client)
        self.assertEqual(r["stored"], 1)
        self.assertEqual(self.store.data, {"b@x.com"})
        self.assertEqual(self.client.listed, {"b@x.com"})

    def test_invalid_action_raises(self):
        with self.assertRaises(ValueError):
            apply_manual("purge", ["a@x.com"], self.store, self.client)

    def test_all_invalid_emails(self):
        r = apply_manual("add", ["nonsense", "", "  "], self.store, self.client)
        self.assertEqual(r["accepted"], [])
        self.assertEqual(len(r["invalid"]), 3)
        self.assertEqual(r["note"], "no valid emails")
        self.assertEqual(self.client.listed, set())

    def test_reconcile_mixed_manual_and_formula(self):
        # The formula wants A, the analyst wants B; both must be in the list, C must be deleted
        self.client.listed = {"c@x.com"}
        apply_manual("add", ["b@x.com"], self.store, self.client)
        desired = reconcile({"a@x.com"}, self.store, self.client)
        self.assertEqual(desired, {"a@x.com", "b@x.com"})
        self.assertEqual(self.client.get_list(), {"a@x.com", "b@x.com"})

    # ---- Tests derived from the Adversary findings (Q4 + Q6) ----

    def test_q4_hostile_inputs_rejected(self):
        # ALL of the inputs the Adversary got through must be invalid now
        hostile = [
            "a@b",                    # no TLD
            "a@@b.com",               # double @
            "a@b,c@d.com",            # joined with a comma
            "a@b\tc.com",             # inner tab (would have broken the RowKey)
            "a@b\nc.com",             # inner newline
            "x" * 1500 + "@y.com",    # over 254
            "<script>@x.com",         # characters outside the RFC
        ]
        r = apply_manual("add", hostile, self.store, self.client)
        self.assertEqual(r["accepted"], [])
        self.assertEqual(len(r["invalid"]), len(hostile))
        self.assertEqual(self.store.data, set())

    def test_q6_push_failure_note_is_honest(self):
        # Wrong actor email: the SOCRadar push returns 0 but it is written to the store.
        # The note must not LIE, it has to give the retry information.
        failing = FakeClient(push_fails=True)
        r = apply_manual("add", ["amy@x.com"], self.store, failing)
        self.assertEqual(r["stored"], 1)
        self.assertEqual(r["pushed"], 0)
        self.assertIn("push incomplete", r["note"])
        self.assertIn("FORMER_ACTOR_EMAIL", r["note"])
        # because it stays in the store, the next reconcile retries the push (self-healing)
        healthy = FakeClient()
        reconcile(set(), self.store, healthy)
        self.assertIn("amy@x.com", healthy.get_list())

    def test_q6_success_note_unchanged(self):
        r = apply_manual("add", ["amy@x.com"], self.store, self.client)
        self.assertIn("added to manual store and SOCRadar list", r["note"])


if __name__ == "__main__":
    unittest.main(verbosity=1)
