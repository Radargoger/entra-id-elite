"""
Data-completeness guard tests (actions/former_guard.py).

The guard closes the adversary finding of 2026-07-24: an HTTP-200 Graph read
with silently incomplete data passes the token gate; the guard catches it by
comparing per-tenant email counts against the last healthy baseline.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from actions.former_guard import evaluate_tenant_counts


class GuardTests(unittest.TestCase):

    def test_first_run_empty_prior_adopts_counts(self):
        res = evaluate_tenant_counts({}, {"t1": 10, "t2": 5})
        self.assertTrue(res.ok)
        self.assertEqual(res.baseline, {"t1": 10, "t2": 5})

    def test_new_tenant_adopted_without_judgement(self):
        res = evaluate_tenant_counts({"t1": 10}, {"t1": 10, "t2": 999})
        self.assertTrue(res.ok)
        self.assertEqual(res.baseline["t2"], 999)

    def test_stable_counts_advance_baseline(self):
        res = evaluate_tenant_counts({"t1": 10}, {"t1": 12})
        self.assertTrue(res.ok)
        self.assertEqual(res.baseline, {"t1": 12})

    def test_zero_read_trips(self):
        res = evaluate_tenant_counts({"t1": 10}, {"t1": 0})
        self.assertFalse(res.ok)
        self.assertIn("zero-read", res.notes[0])

    def test_drop_over_threshold_trips(self):
        res = evaluate_tenant_counts({"t1": 100}, {"t1": 40}, drop_percent=50)
        self.assertFalse(res.ok)

    def test_drop_under_threshold_ok_but_baseline_not_lowered(self):
        # Monotonic baseline: a tolerated sub-threshold drop is NOT adopted.
        res = evaluate_tenant_counts({"t1": 100}, {"t1": 60}, drop_percent=50)
        self.assertTrue(res.ok)
        self.assertEqual(res.baseline["t1"], 100)

    def test_subthreshold_ratchet_is_dead(self):
        # Adversary 2026-07-25: 100->60->36 must NOT slip through in steps.
        r1 = evaluate_tenant_counts({"t1": 100}, {"t1": 60}, drop_percent=50)
        self.assertTrue(r1.ok)
        r2 = evaluate_tenant_counts(r1.baseline, {"t1": 36}, drop_percent=50)
        self.assertFalse(r2.ok)  # 36 vs 100 = 64% drop -> trips
        self.assertEqual(r2.baseline["t1"], 100)  # healthy baseline kept

    def test_tripped_keeps_prior_baseline(self):
        # A bad read must not poison the next comparison.
        res = evaluate_tenant_counts({"t1": 100}, {"t1": 0})
        self.assertEqual(res.baseline, {"t1": 100})

    def test_accept_drop_override_adopts(self):
        res = evaluate_tenant_counts({"t1": 100}, {"t1": 0}, accept_drop=True)
        self.assertTrue(res.ok)
        self.assertEqual(res.baseline["t1"], 0)

    def test_percent_check_disabled_zero_read_still_trips(self):
        ok_drop = evaluate_tenant_counts({"t1": 100}, {"t1": 1}, drop_percent=0)
        self.assertTrue(ok_drop.ok)  # percent check off
        zero = evaluate_tenant_counts({"t1": 100}, {"t1": 0}, drop_percent=0)
        self.assertFalse(zero.ok)    # zero-read always trips

    def test_missing_tenant_not_judged_here(self):
        # Unread tenants are the token gate's job; guard skips them but keeps
        # their prior baseline for the next healthy read.
        res = evaluate_tenant_counts({"t1": 10, "t2": 8}, {"t1": 10})
        self.assertTrue(res.ok)
        self.assertEqual(res.baseline, {"t1": 10, "t2": 8})

    def test_previously_empty_tenant_stays_ok(self):
        res = evaluate_tenant_counts({"t1": 0}, {"t1": 0})
        self.assertTrue(res.ok)


if __name__ == "__main__":
    unittest.main()
