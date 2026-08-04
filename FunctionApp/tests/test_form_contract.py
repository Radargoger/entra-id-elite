"""The portal form and the template have to agree, and the safe defaults
have to stay safe.

An output name in createUiDefinition that no template parameter matches is
dropped by ARM without a word: the field appears, the customer fills it in,
and the deployment behaves as if it were empty. That failure is invisible from
both sides, which is why it is checked here rather than trusted.

The second half pins the two product decisions that a well-meaning edit could
quietly reverse: leaked-credential monitoring ships off, responding ships as
log-only, and the customer is told which responses cannot be undone before
they choose one.

It reads files and nothing else: no app import, no Azure stub, no network.
"""

import json
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
FORM = REPO / "deploy" / "createUiDefinition.json"
TEMPLATE = REPO / "deploy" / "azuredeploy.json"

# Responses that leave no way back. The form has to name them where the
# customer picks a response, not only in the README they may never open.
# Only this one has no way back. The README's undo table gives a route for
# sign-out and password change, so calling those irreversible too diluted the
# warning on the one that matters.
IRREVERSIBLE = ("resetMfa",)


def _form():
    return json.loads(FORM.read_text())


def _steps():
    return {s["name"]: s for s in _form()["parameters"]["steps"]}


def _elements(step_name):
    return {e["name"]: e for e in _steps()[step_name]["elements"]}


class FormTemplateContractTest(unittest.TestCase):

    def test_every_form_output_has_a_template_parameter(self):
        outputs = _form()["parameters"]["outputs"]
        params = json.loads(TEMPLATE.read_text())["parameters"]
        orphans = sorted(k for k in outputs if k not in params)
        self.assertEqual(orphans, [],
                         "ARM drops these silently; the field would do nothing")

    def test_every_form_output_reads_an_element_that_exists(self):
        """steps('x').y where y was renamed resolves to nothing, and the
        deployment proceeds with an empty value."""
        form = _form()
        names = {step: set(_elements(step)) for step in _steps()}
        missing = []
        for out, expr in form["parameters"]["outputs"].items():
            for step, elements in names.items():
                token = f"steps('{step}')."
                text = json.dumps(expr)
                start = 0
                while True:
                    at = text.find(token, start)
                    if at < 0:
                        break
                    rest = text[at + len(token):]
                    ref = ""
                    for ch in rest:
                        if ch.isalnum() or ch == "_":
                            ref += ch
                        else:
                            break
                    if ref and ref not in elements:
                        missing.append(f"{out} -> steps('{step}').{ref}")
                    start = at + len(token)
        self.assertEqual(missing, [])


class GroupTenantsTest(unittest.TestCase):
    """Tenants that belong to the group but have no company row of their own.

    The grid requires a company ID on every row, so such a tenant cannot be
    expressed there; without this field it can only be added by hand after
    deployment.
    """

    def test_the_form_collects_them(self):
        self.assertIn("extraGroupTenants", _elements("socradar"))

    def test_they_are_optional(self):
        """Most deployments have none; requiring it would block them."""
        element = _elements("socradar")["extraGroupTenants"]
        self.assertFalse(element["constraints"]["required"])
        self.assertTrue(element["constraints"]["regex"].startswith("^$|"),
                        "an empty value has to validate")

    def test_the_template_passes_them_to_the_app(self):
        text = TEMPLATE.read_text()
        self.assertIn("GROUP_TENANT_IDS", text)
        self.assertIn("[parameters('GroupTenantIds')]", text)

    def test_the_output_feeds_that_parameter(self):
        outputs = _form()["parameters"]["outputs"]
        self.assertEqual(outputs.get("GroupTenantIds"),
                         "[steps('socradar').extraGroupTenants]")


class LeakDefaultsTest(unittest.TestCase):
    """Shipping defaults decide what happens to a customer who clicks through
    the form without reading it."""

    def test_monitoring_is_off_unless_asked_for(self):
        self.assertIs(_elements("leak")["enableLeak"]["defaultValue"], False)

    def test_the_default_response_changes_nothing(self):
        response = _elements("leak")["response"]
        default_label = response["defaultValue"]
        values = {o["label"]: o["value"]
                  for o in response["constraints"]["allowedValues"]}
        self.assertEqual(values[default_label], "logOnly")

    def test_the_template_agrees_with_the_form(self):
        params = json.loads(TEMPLATE.read_text())["parameters"]
        self.assertIs(params["EnableLeakMonitoring"]["defaultValue"], False)
        self.assertEqual(params["LeakResponse"]["defaultValue"], "logOnly")


class IrreversibilityWarningTest(unittest.TestCase):
    """One response cannot be undone. The customer accepts that risk at the
    moment they pick a response, so the form has to say so there."""

    def _note(self):
        return _elements("leak")["leakNote"]

    def test_the_note_appears_when_responding_is_chosen(self):
        self.assertIn("respond", self._note()["visible"])

    def test_the_note_says_they_cannot_be_undone(self):
        self.assertIn("cannot be undone",
                      self._note()["options"]["text"].lower())

    def test_the_note_names_the_mfa_reset(self):
        """The one with no workaround at all: the methods are gone and the
        person has to enrol again."""
        self.assertIn("mfa", self._note()["options"]["text"].lower())

    def test_every_irreversible_response_is_still_offered_by_the_form(self):
        """If one of these is ever removed, this list is stale and the warning
        describes actions that no longer exist."""
        actions = _elements("leak")["actions"]
        offered = {o["value"] for o in actions["constraints"]["allowedValues"]}
        self.assertTrue(set(IRREVERSIBLE) <= offered,
                        f"warning lists {IRREVERSIBLE}, form offers {offered}")

    def test_the_form_does_not_overstate_how_many_cannot_be_undone(self):
        """Substring checks let the count drift: the note said three while the
        README documented an undo route for two of them, and nothing failed."""
        text = self._note()["options"]["text"]
        self.assertNotIn("Three of these cannot be undone", text)
        self.assertIn("One of these cannot be undone", text)


if __name__ == "__main__":
    unittest.main()
