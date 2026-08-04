"""The group-tenant field has to reach the engine, including the awkward case.

"Other group tenants" exists for a tenant that belongs to the corporate group
but has no company of its own on the platform, a holding tenant being the
example in the form's own help text. The most likely place to deploy from is
that same holding tenant, and that was exactly the input the pipeline dropped.

Silently, too: with the list emptied, group_read == len(group) is 0 == 0, so
the snapshot still counted as complete, removals were not withheld, and the
install looked healthy. A customer would have seen cross-tenant suppression
configured and simply not happening.
"""

import os
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from test_import_path import _ensure_azure_stub  # noqa: E402

_ensure_azure_stub()

from utils import config as cfg  # noqa: E402
from actions import former_companies  # noqa: E402

DEPLOY_TENANT = "aaaaaaaa-1111-2222-3333-444444444444"
HOLDING_TENANT = DEPLOY_TENANT          # deployed from the holding tenant
SIBLING_TENANT = "bbbbbbbb-1111-2222-3333-444444444444"
COMPANY_TENANT = "cccccccc-1111-2222-3333-444444444444"

# What the template actually writes: ENTRA_TENANT_IDS is the deployment tenant
# and OWN_TENANT_IDS is never written at all (deploy/main.bicep).
BASE_ENV = {
    "ENTRA_TENANT_IDS": DEPLOY_TENANT,
    "ENTRA_CLIENT_ID": "11111111-2222-3333-4444-555555555555",
    "STORAGE_ACCOUNT_NAME": "elitestorage",
    "FORMER_COMPANY_MAP": (
        '[{"companyId":"330","tenantIds":"' + COMPANY_TENANT + '",'
        '"apiKey":"k","actorEmail":"a@x.com"}]'
    ),
}


def _load(group_value):
    env = dict(BASE_ENV, GROUP_TENANT_IDS=group_value)
    with mock.patch.dict(os.environ, env, clear=True):
        return cfg.load_former()


class TheHoldingTenantSurvivesLoading(unittest.TestCase):

    def test_a_group_tenant_that_is_the_deployment_tenant_is_kept(self):
        conf = _load(HOLDING_TENANT)
        self.assertIn(HOLDING_TENANT, conf["group_tenant_ids"],
                      "the holding tenant was dropped because the app happens "
                      "to be deployed into it")

    def test_an_unrelated_group_tenant_is_kept(self):
        conf = _load(SIBLING_TENANT)
        self.assertEqual(conf["group_tenant_ids"], [SIBLING_TENANT])

    def test_both_are_kept_together(self):
        conf = _load(f"{HOLDING_TENANT},{SIBLING_TENANT}")
        self.assertEqual(sorted(conf["group_tenant_ids"]),
                         sorted([HOLDING_TENANT, SIBLING_TENANT]))

    def test_an_empty_field_stays_empty(self):
        self.assertEqual(_load("")["group_tenant_ids"], [])


class ExclusionHappensPerCompanyNotAtLoad(unittest.TestCase):
    """Removing a company's own tenants from its group set is per-row work: the
    load step has no idea which company a tenant belongs to. This is why the
    filter moved out of config."""

    def test_a_company_never_gets_its_own_tenant_as_a_group_tenant(self):
        rows = [
            {"company_id": "330", "own_tenants": [COMPANY_TENANT],
             "api_key": "k", "actor_email": "a@x.com"},
            {"company_id": "440", "own_tenants": [SIBLING_TENANT],
             "api_key": "k", "actor_email": "b@x.com"},
        ]
        groups = former_companies.derive_group_tenants(rows, [HOLDING_TENANT])
        self.assertNotIn(COMPANY_TENANT, groups["330"])
        self.assertIn(SIBLING_TENANT, groups["330"])
        self.assertIn(HOLDING_TENANT, groups["330"],
                      "the holding tenant has to reach every company")
        self.assertNotIn(SIBLING_TENANT, groups["440"])
        self.assertIn(HOLDING_TENANT, groups["440"])

    def test_the_holding_tenant_reaches_a_company_in_that_same_tenant(self):
        """The row is in the holding tenant and the holding tenant is also
        listed: it must not appear in that row's group set, and must still
        appear in the other row's."""
        rows = [
            {"company_id": "330", "own_tenants": [HOLDING_TENANT],
             "api_key": "k", "actor_email": "a@x.com"},
            {"company_id": "440", "own_tenants": [SIBLING_TENANT],
             "api_key": "k", "actor_email": "b@x.com"},
        ]
        groups = former_companies.derive_group_tenants(rows, [HOLDING_TENANT])
        self.assertNotIn(HOLDING_TENANT, groups["330"])
        self.assertIn(HOLDING_TENANT, groups["440"])


class TheFormDoesNotPromiseAMockedLeakPath(unittest.TestCase):
    """Client mode selects the former-employee list client and nothing else.
    The tooltip used to read "a self-contained trial, nothing leaves Azure",
    which is untrue with leaked-credential monitoring turned on: the feeds are
    pulled live, addresses go to Microsoft Graph, and under Respond real
    accounts change. A customer choosing Mock as a safe trial would have been
    misled about the half that can actually alter their directory.
    """

    def _tooltip(self):
        import json
        form = json.loads(
            (Path(__file__).resolve().parents[2] /
             "deploy" / "createUiDefinition.json").read_text())
        for step in form["parameters"]["steps"]:
            if step["name"] != "behavior":
                continue
            for element in step["elements"]:
                if element["name"] == "clientMode":
                    return element.get("toolTip", "")
        self.fail("client mode field is gone from the form")

    def test_it_scopes_mock_to_the_former_employee_list(self):
        """Banning the old wording was not enough. An independent review
        rewrote the tooltip as "Mock: a self-contained leak trial, credential
        data stays put", which dodged every banned phrase by a word, restored
        the false promise, and passed all nine tests. So the assertions are on
        what the tooltip must SAY, not on what it must avoid."""
        tip = self._tooltip().lower()
        self.assertIn("former-employee list only", tip,
                      "the tooltip has to state the one thing Mock covers, in "
                      "words a customer cannot read as covering both halves")

    def test_it_says_the_leak_half_always_runs_live(self):
        tip = self._tooltip().lower()
        self.assertIn("always", tip)
        self.assertTrue("pulled live" in tip or "always pulled" in tip,
                        "a customer picking Mock has to be told the feeds are "
                        "still pulled from the live platform")
        self.assertTrue("looked up in entra" in tip or "entra id" in tip,
                        "and that matches are still looked up in the directory")

    def test_it_never_offers_mock_as_a_trial(self):
        """`trial` is the word that made a customer read Mock as safe for the
        half that can change their directory."""
        self.assertNotIn("trial", self._tooltip().lower())


if __name__ == "__main__":
    unittest.main()
