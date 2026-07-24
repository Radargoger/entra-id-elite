"""
P0 safety tests for the ownership-aware reconcile planner and ledger.

These cover the mandatory backlog test list items that are pure/offline:
  - external remote records are preserved (never removal candidates)
  - only owned records are removal candidates
  - first-run / bootstrap delete = 0
  - incomplete snapshot -> mutation = 0
  - add / removal absolute + percentage caps
  - mark_owned / mark_tombstone ledger transitions
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from actions.former_planner import plan_former_reconcile, execute_former_plan, FormerPlan
from actions.former_ownership import InMemoryOwnershipStore, email_hash


class FakeFormerClient:
    """In-memory SOCRadar former list stand-in with faithful readback."""

    def __init__(self, seed=None, drop_adds=None):
        self.listed = set(seed or [])
        # emails the "API" silently refuses to add (e.g. wrong actor) -> readback
        # will not show them, so ownership must NOT be marked.
        self._drop_adds = set(drop_adds or [])

    def get_list(self):
        return set(self.listed)

    def add(self, emails, source):
        for e in emails:
            if e not in self._drop_adds:
                self.listed.add(e)
        return len(emails)

    def remove(self, emails):
        for e in emails:
            self.listed.discard(e)
        return len(emails)


def plan(desired, current, store, *, complete=True, **caps):
    owned = store.owned_among(current)
    return plan_former_reconcile(
        desired=set(desired), current=set(current), owned=owned,
        snapshot_complete=complete, is_bootstrap=store.is_bootstrap(), **caps)


class ExternalRecordSafetyTests(unittest.TestCase):
    def test_external_record_is_preserved_not_removed(self):
        # ext@ was added by the UI (not in the ledger). desired no longer wants
        # it — the OLD formula (current - desired) would delete it. The planner
        # must preserve it.
        store = InMemoryOwnershipStore(seed_owned=["ours@x.com"])
        p = plan(
            desired={"ours@x.com"},
            current={"ours@x.com", "ext@x.com"},
            store=store)
        self.assertEqual(p.remove, [])
        self.assertIn("ext@x.com", p.preserve)
        self.assertFalse(p.blocked)

    def test_only_owned_record_is_a_removal_candidate(self):
        store = InMemoryOwnershipStore(seed_owned=["ours@x.com"])
        # both ours@ and ext@ are current; desired wants neither. Only ours@ is
        # owned -> only ours@ may be removed; ext@ preserved.
        p = plan(
            desired=set(),
            current={"ours@x.com", "ext@x.com"},
            store=store)
        self.assertEqual(p.remove, ["ours@x.com"])
        self.assertEqual(p.preserve, ["ext@x.com"])


class BootstrapTests(unittest.TestCase):
    def test_first_run_never_deletes(self):
        # Empty ledger => bootstrap. Even a formula-derived removal is withheld.
        store = InMemoryOwnershipStore()
        self.assertTrue(store.is_bootstrap())
        p = plan(
            desired={"keep@x.com"},
            current={"keep@x.com", "gone@x.com"},
            store=store)
        self.assertEqual(p.remove, [])
        # gone@ isn't owned yet (bootstrap) so it's external anyway -> preserved,
        # not even a withheld candidate.
        self.assertIn("gone@x.com", p.preserve)

    def test_bootstrap_still_allows_adds(self):
        store = InMemoryOwnershipStore()
        p = plan(desired={"new@x.com"}, current=set(), store=store)
        self.assertEqual(p.add, ["new@x.com"])
        self.assertEqual(p.remove, [])


class SnapshotCompletenessTests(unittest.TestCase):
    def test_incomplete_snapshot_blocks_all_mutation(self):
        store = InMemoryOwnershipStore(seed_owned=["ours@x.com"])
        p = plan(
            desired={"new@x.com"},
            current={"ours@x.com", "ext@x.com"},
            store=store,
            complete=False)
        self.assertTrue(p.blocked)
        self.assertEqual(p.block_reason, "incomplete_snapshot")
        self.assertEqual(p.add, [])
        self.assertEqual(p.remove, [])
        # external records are still reported for audit even when blocked
        self.assertEqual(p.preserve, ["ext@x.com"])


class CapTests(unittest.TestCase):
    def _seeded_store(self, owned):
        return InMemoryOwnershipStore(seed_owned=owned)

    def test_absolute_removal_cap_withholds_all_removals(self):
        owned = [f"u{i}@x.com" for i in range(5)]
        store = self._seeded_store(owned)
        p = plan(desired=set(), current=set(owned), store=store, max_removals=3)
        self.assertEqual(p.remove, [])
        self.assertEqual(len(p.withheld_removals), 5)

    def test_removal_percent_cap_withholds_all_removals(self):
        owned = [f"u{i}@x.com" for i in range(6)]
        store = self._seeded_store(owned)
        # removing all 6 of 6 current = 100% > 50%
        p = plan(desired=set(), current=set(owned), store=store,
                 max_removals=100, max_removal_percent=50)
        self.assertEqual(p.remove, [])
        self.assertEqual(len(p.withheld_removals), 6)

    def test_removals_within_caps_proceed(self):
        owned = [f"u{i}@x.com" for i in range(10)]
        store = self._seeded_store(owned)
        # remove 3 of 10 = 30% < 50%, abs 3 <= 5
        desired = {"u0@x.com", "u1@x.com", "u2@x.com", "u3@x.com", "u4@x.com",
                   "u5@x.com", "u6@x.com"}
        p = plan(desired=desired, current=set(owned), store=store,
                 max_removals=5, max_removal_percent=50)
        self.assertEqual(sorted(p.remove), ["u7@x.com", "u8@x.com", "u9@x.com"])

    def test_absolute_add_cap_withholds_adds_only(self):
        store = self._seeded_store([])
        desired = {f"n{i}@x.com" for i in range(10)}
        p = plan(desired=desired, current=set(), store=store, max_adds=4)
        self.assertEqual(p.add, [])
        self.assertFalse(p.blocked)


class LedgerTransitionTests(unittest.TestCase):
    def test_mark_owned_then_owned_among(self):
        store = InMemoryOwnershipStore()
        store.mark_owned(["a@x.com", "b@x.com"])
        self.assertFalse(store.is_bootstrap())
        self.assertEqual(store.owned_among(["a@x.com", "c@x.com"]), {"a@x.com"})

    def test_tombstone_removes_from_owned(self):
        store = InMemoryOwnershipStore(seed_owned=["a@x.com"])
        store.mark_tombstone(["a@x.com"])
        self.assertEqual(store.owned_among(["a@x.com"]), set())

    def test_hash_is_case_and_space_insensitive(self):
        self.assertEqual(email_hash(" A@X.com "), email_hash("a@x.com"))

    def test_owned_among_is_intersected_with_current(self):
        # a record owned in the ledger but no longer current must not appear.
        store = InMemoryOwnershipStore(seed_owned=["old@x.com"])
        self.assertEqual(store.owned_among(["new@x.com"]), set())


class RegressionOldFormulaTests(unittest.TestCase):
    def test_planner_diverges_from_naive_current_minus_desired(self):
        # The exact scenario PRODUCTION-BLOCKED warns about.
        store = InMemoryOwnershipStore(seed_owned=["ours@x.com"])
        current = {"ours@x.com", "ui-added@x.com"}
        desired = {"ours@x.com"}
        naive_remove = sorted(current - desired)   # old code
        p = plan(desired=desired, current=current, store=store)
        self.assertEqual(naive_remove, ["ui-added@x.com"])   # old code would delete it
        self.assertNotIn("ui-added@x.com", p.remove)         # planner never does
        self.assertIn("ui-added@x.com", p.preserve)


class CapZeroSemanticsTests(unittest.TestCase):
    def test_max_removals_zero_means_none_allowed(self):
        owned = ["u0@x.com", "u1@x.com"]
        store = InMemoryOwnershipStore(seed_owned=owned)
        p = plan(desired=set(), current=set(owned), store=store, max_removals=0)
        self.assertEqual(p.remove, [])
        self.assertEqual(len(p.withheld_removals), 2)

    def test_max_removals_none_means_no_cap(self):
        owned = [f"u{i}@x.com" for i in range(300)]
        store = InMemoryOwnershipStore(seed_owned=owned)
        p = plan(desired=set(), current=set(owned), store=store,
                 max_removals=None, max_removal_percent=100)
        self.assertEqual(len(p.remove), 300)


class ExecutePlanWiringTests(unittest.TestCase):
    """The apply/plan-only/readback branch — the risky wiring the sync runs."""

    def test_plan_only_makes_no_mutation_and_no_ledger_change(self):
        store = InMemoryOwnershipStore()
        client = FakeFormerClient()
        p = plan_former_reconcile(
            desired={"new@x.com"}, current=set(), owned=set(),
            snapshot_complete=True, is_bootstrap=True)
        r = execute_former_plan(p, client, store, apply_changes=False)
        self.assertFalse(r["applied"])
        self.assertEqual(client.get_list(), set())
        self.assertTrue(store.is_bootstrap())

    def test_apply_add_marks_owned_after_readback(self):
        store = InMemoryOwnershipStore()
        client = FakeFormerClient()
        p = plan_former_reconcile(
            desired={"new@x.com"}, current=set(), owned=set(),
            snapshot_complete=True, is_bootstrap=True)
        r = execute_former_plan(p, client, store, apply_changes=True)
        self.assertTrue(r["applied"])
        self.assertEqual(r["added"], 1)
        self.assertIn("new@x.com", client.get_list())
        self.assertEqual(store.owned_among(["new@x.com"]), {"new@x.com"})

    def test_apply_remove_marks_tombstone_after_readback(self):
        store = InMemoryOwnershipStore(seed_owned=["gone@x.com"])
        client = FakeFormerClient(seed=["gone@x.com"])
        p = plan_former_reconcile(
            desired=set(), current={"gone@x.com"}, owned={"gone@x.com"},
            snapshot_complete=True, is_bootstrap=False, max_removals=100)
        r = execute_former_plan(p, client, store, apply_changes=True)
        self.assertEqual(r["removed"], 1)
        self.assertNotIn("gone@x.com", client.get_list())
        self.assertEqual(store.owned_among(["gone@x.com"]), set())

    def test_blocked_plan_never_mutates(self):
        store = InMemoryOwnershipStore(seed_owned=["ours@x.com"])
        client = FakeFormerClient(seed=["ours@x.com"])
        p = FormerPlan(blocked=True, block_reason="incomplete_snapshot")
        r = execute_former_plan(p, client, store, apply_changes=True)
        self.assertFalse(r["applied"])
        self.assertIn("ours@x.com", client.get_list())

    def test_add_readback_mismatch_does_not_mark_owned(self):
        # The API silently drops the add (e.g. wrong actor). Readback shows it
        # absent -> confirmed < planned AND ownership NOT recorded (no false own).
        store = InMemoryOwnershipStore()
        client = FakeFormerClient(drop_adds=["ghost@x.com"])
        p = plan_former_reconcile(
            desired={"ghost@x.com"}, current=set(), owned=set(),
            snapshot_complete=True, is_bootstrap=True)
        r = execute_former_plan(p, client, store, apply_changes=True)
        self.assertEqual(r["add_planned"], 1)
        self.assertEqual(r["added"], 0)
        self.assertEqual(store.owned_among(["ghost@x.com"]), set())


if __name__ == "__main__":
    unittest.main()
