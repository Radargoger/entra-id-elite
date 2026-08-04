"""The manual endpoint is an override, and the README has to say so.

Two safety sentences used to be written without qualification: that plan-only
mode writes nothing, and that records the integration did not create are never
touched. Both hold for the scheduled reconcile. Neither holds for
`POST /api/former/manual`, which writes what it is given in either mode and
removes exactly the addresses it is handed. Stating them unqualified made the
product sound safer than it is.
"""

import re
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import test_import_path  # noqa: E402,F401  (installs the azure stubs)
from actions import former_manual  # noqa: E402

REPO = Path(__file__).resolve().parents[2]


class _Store:
    def __init__(self):
        self.added, self.removed = [], []

    def add(self, e):
        self.added += list(e)
        return len(e)

    def remove(self, e):
        self.removed += list(e)
        return len(e)

    def list(self):
        return set(self.added) - set(self.removed)


class _Client:
    def __init__(self):
        self.added, self.removed = [], []

    def add(self, e, source=""):
        self.added += list(e)
        return len(e)

    def remove(self, e):
        self.removed += list(e)
        return len(e)

    def get_list(self):
        return set(self.added) - set(self.removed)


class TheManualEndpointWritesRegardlessOfMode(unittest.TestCase):
    """It is an operator override, not something the apply switch gates."""

    def _run(self, action, emails):
        store, client = _Store(), _Client()
        former_manual.apply_manual(action, emails, store, client)
        return store, client

    def test_add_reaches_the_platform(self):
        _, client = self._run("add", ["a@example.com"])
        self.assertEqual(client.added, ["a@example.com"])

    def test_remove_takes_the_address_it_is_given(self):
        _, client = self._run("remove", ["someone-elses@example.com"])
        self.assertEqual(
            client.removed, ["someone-elses@example.com"],
            "the manual path does not consult the ownership ledger; the README "
            "must not claim otherwise")

    def test_nothing_in_this_path_reads_the_apply_switch(self):
        source = (REPO / "FunctionApp" / "actions" / "former_manual.py").read_text(encoding="utf-8")
        self.assertNotIn(
            "apply_changes", source,
            "if the manual path ever gains an apply gate, the README sentence "
            "calling it an override has to change with it")


class TheReadmeSaysWhichPathItMeans(unittest.TestCase):
    """Both safety sentences are scoped, so neither reads as a blanket promise."""

    def setUp(self):
        self.readme = (REPO / "README.md").read_text(encoding="utf-8")

    def test_plan_only_names_the_manual_exception(self):
        window = self.readme[:self.readme.find("## Deploy")]
        self.assertRegex(
            window, r"plan-only mode\)\.[\s\S]{0,200}former/manual",
            "plan-only is stated without saying the manual endpoint still writes")

    def test_the_ownership_promise_is_scoped_to_the_reconcile(self):
        m = re.search(r"never touched by it[\s\S]{0,300}", self.readme)
        self.assertIsNotNone(m, "the ownership sentence is unqualified again")
        self.assertIn("manual", m.group(0),
                      "the exception has to sit with the claim, not elsewhere")


class TheFormCountsIrreversibleActionsCorrectly(unittest.TestCase):
    """Only the MFA reset cannot be undone; the README table is the truth."""

    def setUp(self):
        import json
        ui = json.loads((REPO / "deploy" / "createUiDefinition.json").read_text(encoding="utf-8"))
        self.texts = [e["options"]["text"]
                      for s in ui["parameters"]["steps"] for e in s["elements"]
                      if e.get("type") == "Microsoft.Common.TextBlock"]

    def test_the_form_does_not_claim_three(self):
        joined = " ".join(self.texts)
        self.assertNotIn(
            "Three of these cannot be undone", joined,
            "the README gives an undo route for sign-out and password change; "
            "crying wolf on three dilutes the one that matters")

    def test_the_form_still_warns_about_the_one_that_counts(self):
        joined = " ".join(self.texts).lower()
        self.assertIn("cannot be undone", joined)
        self.assertIn("mfa", joined)


if __name__ == "__main__":
    unittest.main()
