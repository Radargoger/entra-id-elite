"""
Former audit + preview builder tests (actions/former_audit.py).

Locks the two PII postures of option (a), 2026-07-25:
  - LAW audit rows: hashed emails ONLY, never a clear address.
  - Preview payload: clear emails for plan/populations, preserve COUNT-ONLY,
    capped listings.
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from actions.former_audit import (
    build_former_audit_rows, build_preview_payload, PREVIEW_LIST_CAP)
from actions.former_ownership import email_hash
from actions.former_planner import FormerPlan


def _plan(**kw):
    defaults = dict(add=["add1@x.com"], remove=["rem1@x.com"],
                    preserve=["ext1@x.com", "ext2@x.com"],
                    withheld_removals=["wh1@x.com"], notes=["note-a"])
    defaults.update(kw)
    return FormerPlan(**defaults)


STATS = {"own_active": 5, "own_former": 2, "sibling_active": 3, "manual": 1,
         "desired": 6, "review_needed": 0, "snapshot_complete": True}


class AuditRowTests(unittest.TestCase):

    def test_summary_row_first_with_counts(self):
        rows = build_former_audit_rows("330", STATS, _plan(),
                                       {"applied": True, "added": 1, "removed": 1},
                                       "real", True)
        head = rows[0]
        self.assertEqual(head["event_type"], "former_reconcile_summary")
        self.assertEqual(head["company_id"], "330")
        self.assertEqual(head["add_planned"], 1)
        self.assertEqual(head["remove_planned"], 1)
        self.assertEqual(head["withheld"], 1)
        self.assertEqual(head["preserve"], 2)

    def test_one_row_per_action_with_hash(self):
        rows = build_former_audit_rows("330", STATS, _plan(),
                                       {"applied": True, "added": 1, "removed": 1},
                                       "real", True)
        actions = rows[1:]
        self.assertEqual(len(actions), 3)  # 1 add + 1 remove + 1 withheld
        by_type = {r["event_type"]: r for r in actions}
        self.assertEqual(by_type["former_add"]["email_sha256"], email_hash("add1@x.com"))
        self.assertTrue(by_type["former_add"]["applied"])
        self.assertTrue(by_type["former_remove"]["applied"])
        self.assertFalse(by_type["former_removal_withheld"]["applied"])

    def test_no_clear_email_anywhere_in_audit(self):
        rows = build_former_audit_rows("330", STATS, _plan(),
                                       {"applied": False, "added": 0, "removed": 0},
                                       "mock", False)
        dump = json.dumps(rows)
        for email in ("add1@x.com", "rem1@x.com", "ext1@x.com", "wh1@x.com"):
            self.assertNotIn(email, dump)

    def test_plan_only_marks_nothing_applied(self):
        rows = build_former_audit_rows("330", STATS, _plan(),
                                       {"applied": False, "added": 0, "removed": 0},
                                       "mock", False)
        self.assertTrue(all(not r["applied"] for r in rows[1:]))


class PreviewTests(unittest.TestCase):

    FCONF = {"socradar_company_id": "330", "former_client_mode": "mock",
             "former_apply_changes": False, "ruleset_mode": "standart"}

    def _payload(self, plan=None, populations=None):
        return build_preview_payload(
            STATS,
            populations or {"own_disabled": {"d1@x.com"}, "own_deleted": {"del1@x.com"},
                            "sibling_active": {"s1@x.com"}},
            plan or _plan(), {"man1@x.com"}, self.FCONF, ["guard-note"])

    def test_clear_emails_in_plan_and_populations(self):
        p = self._payload()
        self.assertIn("add1@x.com", p["plan"]["add"]["emails"])
        self.assertIn("d1@x.com", p["populations"]["own_disabled"]["emails"])
        self.assertIn("man1@x.com", p["manual"]["emails"])

    def test_preserve_is_count_only(self):
        p = self._payload()
        self.assertEqual(p["plan"]["preserve_count"], 2)
        self.assertNotIn("ext1@x.com", json.dumps(p))  # external PII never listed

    def test_listing_capped_with_truncated_flag(self):
        big = {f"u{i}@x.com" for i in range(PREVIEW_LIST_CAP + 50)}
        p = self._payload(populations={"own_disabled": big, "own_deleted": set(),
                                       "sibling_active": set()})
        listing = p["populations"]["own_disabled"]
        self.assertEqual(listing["count"], PREVIEW_LIST_CAP + 50)
        self.assertEqual(len(listing["emails"]), PREVIEW_LIST_CAP)
        self.assertTrue(listing["truncated"])

    def test_guard_notes_and_flags_surfaced(self):
        p = self._payload()
        self.assertEqual(p["guard_notes"], ["guard-note"])
        self.assertFalse(p["apply_changes"])
        self.assertTrue(p["snapshot_complete"])


if __name__ == "__main__":
    unittest.main()
