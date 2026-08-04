"""Three README claims a customer bases an irreversible decision on.

Each one was wrong. The code was right in all three cases — the text was not,
and the text is what someone reads before switching on MFA resets:

  1. "a ceiling per run" — the ceiling is per company per source, so the real
     maximum is 50 x companies x sources. A three-company, two-source install
     could change 300 accounts in a run someone believed was capped at 50.
  2. "an incomplete snapshot withholds deletions" — it withholds everything,
     additions included, so a tenant that never consented suppresses nobody
     while the operator believes only cleanup is paused.
  3. "recorded as confirm_risky_failed and retried on a later run" — nothing
     retries it. The window moves on and those people are never processed.

These tests pin the behaviour and the sentence to each other. Change one and
the other has to follow.
"""

import ast
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import test_import_path  # noqa: E402,F401  (installs the azure stubs)

REPO = Path(__file__).resolve().parents[2]
SRC = (REPO / "FunctionApp" / "function_app.py").read_text(encoding="utf-8")


def prose(path) -> str:
    """The document as a reader sees it: unwrapped, without markdown emphasis.

    A phrase that straddles a line break is the same sentence to a reader.
    Matching the raw file made these assertions depend on where a paragraph
    happened to wrap rather than on what it said.
    """
    return " ".join(path.read_text(encoding="utf-8").replace("*", "").split())


README = prose(REPO / "README.md")
DEPLOY_README = prose(REPO / "deploy" / "README.md")


class TheCeilingIsPerCompanyPerSource(unittest.TestCase):

    def _process_source_fn(self):
        tree = ast.parse(SRC)
        return next(n for n in ast.walk(tree)
                    if isinstance(n, ast.FunctionDef) and n.name == "_process_source")

    def test_the_counter_resets_on_every_call(self):
        """A parameter would carry it across sources; a local assignment cannot."""
        fn = self._process_source_fn()
        params = [a.arg for a in fn.args.args]
        self.assertNotIn("actions", params,
                         "the counter is threaded in — the ceiling may now be run-wide, "
                         "so the README sentence needs revisiting")
        # The counter is set in a chain (`found = not_found = actions = ... = 0`),
        # so every target of every assignment has to be walked, not just the first.
        assigned = [n.lineno for n in ast.walk(fn) if isinstance(n, ast.Assign)
                    for target in n.targets
                    for t in (target.elts if isinstance(target, (ast.Tuple, ast.List))
                              else [target])
                    if isinstance(t, ast.Name) and t.id == "actions"]
        self.assertTrue(assigned,
                        "no local 'actions' counter found — the ceiling moved somewhere else")

    def test_it_is_called_once_per_company_per_source(self):
        tree = ast.parse(SRC)
        calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
                 and isinstance(n.func, ast.Name) and n.func.id == "_process_source"]
        self.assertTrue(calls, "_process_source is never called?")
        # Each call sits inside two nested for-loops (companies, then sources).
        depth_ok = False
        for parent in ast.walk(tree):
            if not isinstance(parent, ast.For):
                continue
            inner_fors = [n for n in ast.walk(parent) if isinstance(n, ast.For) and n is not parent]
            for inner in inner_fors:
                if any(c in ast.walk(inner) for c in calls):
                    depth_ok = True
        self.assertTrue(depth_ok,
                        "the call is no longer inside a company x source nesting — "
                        "recheck what the ceiling actually bounds")

    def test_both_readmes_say_so(self):
        self.assertIn("per company per source", README,
                      "README must not describe the ceiling as a whole-run limit")
        self.assertIn("per company per source", DEPLOY_README)

    def test_the_readme_does_not_call_it_a_per_run_ceiling(self):
        self.assertNotIn("A ceiling per run", README)


class AnIncompleteSnapshotStopsAdditionsToo(unittest.TestCase):

    def test_the_planner_withholds_both_sides(self):
        from actions.former_planner import plan_former_reconcile
        plan = plan_former_reconcile(
            desired={"a@example.com", "b@example.com"}, current=set(), owned=set(),
            snapshot_complete=False, is_bootstrap=False)
        self.assertEqual(plan.add, [], "an incomplete snapshot must not add either")
        self.assertEqual(plan.remove, [])
        self.assertTrue(plan.blocked)
        self.assertEqual(plan.block_reason, "incomplete_snapshot")

    def test_bootstrap_by_contrast_still_adds(self):
        """The two are different, which is why one sentence cannot cover both."""
        from actions.former_planner import plan_former_reconcile
        plan = plan_former_reconcile(
            desired={"a@example.com"}, current={"z@example.com"}, owned={"z@example.com"},
            snapshot_complete=True, is_bootstrap=True)
        self.assertEqual(sorted(plan.add), ["a@example.com"])
        self.assertEqual(plan.remove, [], "bootstrap withholds removals only")

    def test_the_readme_says_additions_stop_as_well(self):
        self.assertIn("additions included", README)
        self.assertNotIn(
            "An incomplete tenant snapshot, the first run, and per-run caps all", README,
            "that sentence lumped the incomplete snapshot in with the two guards "
            "that really do withhold deletions only")


class AFailedResponseIsNotRetried(unittest.TestCase):

    def test_nothing_about_a_failed_action_holds_the_window(self):
        start = SRC.find("hold_checkpoint = (")
        self.assertNotEqual(start, -1, "the checkpoint hold expression moved")
        expr = SRC[start:SRC.find(")", start) + 1]
        self.assertNotIn("action", expr,
                         "a failed action now holds the window — the README may "
                         "promise a retry again, and this time it would be true")

    def test_the_readme_does_not_promise_a_retry(self):
        self.assertNotIn("retried on a later run", README)
        self.assertIn("not processed again on a later run", README)


if __name__ == "__main__":
    unittest.main()
