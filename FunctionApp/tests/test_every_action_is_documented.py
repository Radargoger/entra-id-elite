"""Every change this app can make to a directory has to be written down.

The README's "Undoing a response" table listed five actions. The code could
take eight. Adding people to a security group was one of the missing three, and
it is on by default -- it needs no checkbox, only a group id in the form. So a
customer could have members added to a security group with nothing in the
documentation telling them it would happen or how to reverse it.

The list is not repeated here by hand. It is read out of the dispatch block in
function_app.py, so an action added later fails this test instead of quietly
becoming another undocumented directory change.
"""

import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

REPO = Path(__file__).resolve().parents[2]
SRC = (REPO / "FunctionApp" / "function_app.py").read_text(encoding="utf-8")
README = (REPO / "README.md").read_text(encoding="utf-8")

# The row in the undo table that covers each action. Keys are the action names
# the code files in `actions_taken`; values are a phrase that must appear in
# that table. Fail loudly when an action is not here at all -- that is the case
# this file exists to catch.
DOCUMENTED = {
    "revoke_session":        "Sign the user out everywhere",
    "add_to_group":          "Add to a security group",
    "remove_from_group":     "Remove from a security group",
    "disable_account":       "Disable the account",
    "enable_account":        "Re-enable the account",
    "force_password_change": "Require a password change",
    "confirm_risky":         "Confirm compromised",
    "force_mfa_rereg":       "Reset MFA registration",
}


def dispatched_actions():
    """Action names the run can file, read from the source."""
    names = set(re.findall(r'planned\.append\(\("([a-z_]+)"', SRC))
    # force_mfa_rereg sits outside the loop because it reports its own outcome;
    # picking it up by its recorded name keeps this independent of that shape.
    names |= {m for m in re.findall(r'taken\.append\("([a-z_]+)_planned"\)', SRC)}
    return names


def undo_table():
    """The rows of the 'Undoing a response' table."""
    start = README.find("### Undoing a response")
    assert start != -1, "the undo table is gone from the README"
    body = README[start:README.find("\n## ", start)]
    return [line for line in body.splitlines() if line.startswith("|")]


class EveryActionTheCodeCanTakeIsInTheUndoTable(unittest.TestCase):

    def test_no_action_is_missing_from_the_map(self):
        unmapped = sorted(dispatched_actions() - set(DOCUMENTED))
        self.assertEqual(
            unmapped, [],
            f"these directory changes have no documented way to undo them: {unmapped}")

    def test_each_one_has_a_row(self):
        rows = "\n".join(undo_table())
        missing = sorted(name for name, phrase in DOCUMENTED.items()
                         if name in dispatched_actions() and phrase not in rows)
        self.assertEqual(
            missing, [],
            f"the code takes these actions but the undo table does not list them: {missing}")

    def test_the_group_action_is_marked_as_not_a_checkbox(self):
        """It is enabled by a text field, which reads as configuration, not consent."""
        start = README.find("### Undoing a response")
        body = README[start:README.find("\n## ", start)]
        self.assertIn("Security group object ID", body)
        self.assertIn("not checkboxes", body)


class TheTableDoesNotPromiseMoreThanEntraAllows(unittest.TestCase):

    def test_mfa_reset_is_still_called_irreversible(self):
        rows = "\n".join(undo_table())
        self.assertIn("Cannot be undone", rows,
                      "MFA reset is the one action nobody can walk back; "
                      "if this line goes, the warning goes with it")


class TheFormOffersFewerThanTheCodeCanDo(unittest.TestCase):
    """Not a defect -- but the gap has to stay visible in the README."""

    def test_actions_absent_from_the_form_are_named_with_their_setting(self):
        import json
        ui = json.loads((REPO / "deploy" / "createUiDefinition.json").read_text(encoding="utf-8"))
        offered = set()

        def walk(o):
            if isinstance(o, dict):
                if o.get("name") == "actions":
                    for c in o.get("constraints", {}).get("allowedValues", []):
                        offered.add(c.get("value"))
                for v in o.values():
                    walk(v)
            elif isinstance(o, list):
                for v in o:
                    walk(v)
        walk(ui)
        self.assertTrue(offered, "the response-actions control disappeared from the form")
        # These two are reachable only by setting an app setting by hand, so the
        # README has to say which one, or nobody can find them or turn them off.
        for setting in ("ENABLE_REMOVE_FROM_GROUP", "ENABLE_ENABLE_ACCOUNT"):
            self.assertIn(setting, README,
                          f"{setting} changes the directory but is not on the form; "
                          "the README has to name it")


if __name__ == "__main__":
    unittest.main()
