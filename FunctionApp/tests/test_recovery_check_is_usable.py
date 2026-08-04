"""The check we tell people to run has to be able to say yes.

When the federated credential is missing, the deployment still reports success
and the template hands back a note telling the operator how to confirm it. That
note used to point at `leak/preview`, whose reachability list is empty whenever
leak monitoring is off. Leak monitoring is off by default, so for a
former-employee-only install the recommended check answered "credential
missing" every time, correct install or not, and could not tell the two apart.
"""

import json
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import test_import_path  # noqa: E402,F401  (installs the azure stubs)
import function_app  # noqa: E402

REPO = Path(__file__).resolve().parents[2]


class TheTemplateSendsPeopleToACheckThatCanDistinguish(unittest.TestCase):

    def setUp(self):
        self.arm = json.loads((REPO / "deploy" / "azuredeploy.json").read_text(encoding="utf-8"))
        self.note = json.dumps(self.arm["outputs"]["ficNote"])

    def test_it_does_not_send_them_to_the_leak_endpoint(self):
        self.assertNotIn(
            "GET /api/leak/preview", self.note,
            "leak/preview reports nothing reachable while leak monitoring is off, "
            "so it cannot confirm a credential on the default install")

    def test_it_sends_them_to_the_one_that_works_either_way(self):
        self.assertIn("GET /api/former/preview", self.note)

    def test_it_names_what_to_look_at(self):
        self.assertIn("snapshot_complete", self.note)


class WhyLeakPreviewCannotAnswerIt(unittest.TestCase):
    """The reachability list is gated on user lookup, which follows leak."""

    def test_the_template_ties_lookup_to_leak_monitoring(self):
        bicep = (REPO / "deploy" / "main.bicep").read_text(encoding="utf-8")
        self.assertIn(
            "{ name: 'ENABLE_USER_LOOKUP', value: string(EnableLeakMonitoring) }", bicep,
            "if this ever decouples, leak/preview becomes usable as an install "
            "check again and the note may point back at it")

    def test_with_lookup_off_no_tenant_is_reported_reachable(self):
        conf = {
            "socradar_company_id": "1", "socradar_api_key": "k",
            "enable_user_lookup": False, "enable_botnet_source": True,
            "enable_pii_source": False, "enable_vip_source": False,
            "company_map_raw": "", "tenant_ids": ["t1"],
            "entra_action_mode": "plan", "entra_max_actions_per_run": 50,
            "security_group_id": "", "enable_revoke_session": False,
            "enable_password_change": False, "enable_disable_account": False,
            "enable_enable_account": False, "enable_confirm_risky": False,
            "enable_force_mfa_reregistration": False, "enable_add_to_group": False,
        }
        with mock.patch.object(function_app.cfg, "load", return_value=conf), \
             mock.patch.object(function_app, "_import_company_rows",
                               return_value=[{"company_id": "1", "api_key": "k",
                                              "own_tenants": ["t1"]}]), \
             mock.patch.object(function_app, "_import_company_conf",
                               return_value=dict(conf, tenant_ids=["t1"])), \
             mock.patch.object(function_app, "_acquire_tenant_tokens") as tokens:
            body = function_app.leak_preview(mock.Mock(params={}))
            payload = json.loads(body.get_body().decode())
        self.assertFalse(tokens.called,
                         "no token is even attempted, so an empty list says "
                         "nothing about the credential")
        company = payload["companies"][0]
        self.assertEqual(company["tenants_reachable"], [])
        self.assertFalse(company["ready"],
                         "this false is what the old note read as 'credential missing'")


if __name__ == "__main__":
    unittest.main()
