"""Four decisions taken on 30 July, pinned so they cannot drift back.

Each of them was a gap a cautious customer would have found: an audit trail
that could not be checked against anything, every address in a feed forwarded
to Microsoft, a first leak run that never came, and two places to look for one
answer. None of them was a coding mistake, which is why nothing failed.
"""

import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from test_import_path import _ensure_azure_stub  # noqa: E402

_ensure_azure_stub()

from actions import law_writer  # noqa: E402
import function_app  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
TEMPLATE = json.loads((REPO / "deploy" / "azuredeploy.json").read_text())
FORM = json.loads((REPO / "deploy" / "createUiDefinition.json").read_text())
BICEP = (REPO / "deploy" / "main.bicep").read_text()


def _function_app_settings():
    """Names written into the running app's own configuration."""
    resources = TEMPLATE["resources"]
    resources = resources.values() if isinstance(resources, dict) else resources
    text = "".join(json.dumps(r) for r in resources
                   if "Microsoft.Web/sites" in str(r.get("type", "")))
    return text


class TheObjectIdReachesTheAuditTable(unittest.TestCase):
    """`entra_user_id` is the only field that joins a row in Log Analytics to
    Microsoft Entra ID's own audit log. Without it a customer cannot confirm
    from an independent source that a change the app reports really happened,
    which is the first thing anyone asks before granting write permission.

    It has to arrive in both places at once. Writing it without declaring it in
    the collection rule is worse than not writing it: the rule drops undeclared
    columns and the upload still reports success. This is a documented failure class.
    """

    def test_the_written_record_keeps_it(self):
        record = {"email": "a@x.com", "entra_user_id": "obj-1234",
                  "entra_status": "found"}
        with mock.patch.object(law_writer, "_upload", return_value=True) as up:
            law_writer.write_records(
                {"dcr_immutable_id": "d", "dcr_endpoint": "https://x.invalid",
                 "socradar_company_id": "330"}, "botnet", [record])
        sent = up.call_args[0][2][0]
        self.assertEqual(sent.get("entra_user_id"), "obj-1234",
                         "the object ID was stripped again, so nothing can be "
                         "matched against Entra's own audit log")

    def test_the_collection_rule_declares_it(self):
        self.assertIn("entra_user_id", json.dumps(TEMPLATE),
                      "the column is not declared, so the rule will drop it "
                      "silently while the upload reports success")

    def test_it_is_declared_for_every_leak_source(self):
        """Declared once in the shared column list, not per source, so a new
        source cannot forget it."""
        self.assertIn("entra_user_id", BICEP.split("var botnetColumns")[0],
                      "declare it in leakCommonColumns, not per source")


class AddressesOutsideOurDomainsNeverLeave(unittest.TestCase):
    """A leak feed can name anyone. Before this, every address it returned was
    sent to Microsoft Graph to be looked up, whether or not it had anything to
    do with the customer."""

    def test_the_form_asks_for_the_domains(self):
        leak = next(s for s in FORM["parameters"]["steps"]
                    if s["name"] == "leak")
        names = [e["name"] for e in leak["elements"]]
        self.assertIn("verifiedDomains", names)

    def test_it_is_optional_and_empty_validates(self):
        leak = next(s for s in FORM["parameters"]["steps"]
                    if s["name"] == "leak")
        field = next(e for e in leak["elements"]
                     if e["name"] == "verifiedDomains")
        self.assertFalse(field["constraints"]["required"])
        self.assertTrue(field["constraints"]["regex"].startswith("^$|"))

    def test_the_form_output_feeds_the_template(self):
        self.assertEqual(FORM["parameters"]["outputs"].get("VerifiedDomains"),
                         "[steps('leak').verifiedDomains]")
        self.assertIn("VerifiedDomains", TEMPLATE["parameters"])

    def test_the_template_passes_it_to_the_app(self):
        self.assertIn("ENTRA_ID_VERIFIED_DOMAINS", _function_app_settings())

    def test_an_outside_address_is_dropped_before_any_lookup(self):
        """The gate has to sit in front of the lookup, not after it: the point
        is that the address never reaches Microsoft."""
        looked_up = []

        def fake_lookup(email, headers):
            looked_up.append(email)
            return ({"id": "uid", "accountEnabled": True}, 200)

        conf = _leak_conf(verified_domains=["corp.com"])
        with mock.patch.object(function_app.src_botnet, "fetch",
                               return_value=[{"email": "stranger@other.com"},
                                             {"email": "ours@corp.com"}]), \
             mock.patch.object(function_app.cp, "load", return_value={}), \
             mock.patch.object(function_app.cp, "save"), \
             mock.patch.object(function_app.law, "write_records", return_value=True), \
             mock.patch.object(function_app.entra, "lookup_user",
                               side_effect=fake_lookup):
            result = function_app._process_source(
                "botnet", conf, None, {"t-a": {"h": "x"}},
                deadline=float("inf"), checkpoint_key="botnet:330")

        self.assertEqual(looked_up, ["ours@corp.com"],
                         "an address outside the customer's domains was sent "
                         "to Microsoft Graph")
        self.assertEqual(result["domain_filtered"], 1)

    def test_an_empty_list_looks_everything_up(self):
        """Existing installs set nothing, and their behaviour must not change."""
        looked_up = []
        conf = _leak_conf(verified_domains=[])
        with mock.patch.object(function_app.src_botnet, "fetch",
                               return_value=[{"email": "stranger@other.com"}]), \
             mock.patch.object(function_app.cp, "load", return_value={}), \
             mock.patch.object(function_app.cp, "save"), \
             mock.patch.object(function_app.law, "write_records", return_value=True), \
             mock.patch.object(function_app.entra, "lookup_user",
                               side_effect=lambda e, h: (looked_up.append(e),
                                                         ({"id": "u"}, 200))[1]):
            function_app._process_source(
                "botnet", conf, None, {"t-a": {"h": "x"}},
                deadline=float("inf"), checkpoint_key="botnet:330")
        self.assertEqual(looked_up, ["stranger@other.com"])


class TheFirstLeakRunHappens(unittest.TestCase):
    """The leak timer was pinned off at startup while the former sync ran, so a
    customer who turned leak monitoring on saw nothing for up to six hours and
    had no way to tell that from a broken install."""

    def test_it_follows_the_same_switch_as_the_former_sync(self):
        settings = _function_app_settings()
        self.assertIn("RUN_ON_STARTUP", settings)
        self.assertNotIn('"name": "RUN_ON_STARTUP", "value": "false"',
                         settings.replace("'", '"'),
                         "pinned off again")
        # The template stringifies the boolean, so match the parameter
        # reference rather than a literal rendering of it.
        self.assertIn("parameters('RunOnStartup')", settings)
        leak_setting = next(
            s for s in json.loads(settings)["properties"]["siteConfig"]["appSettings"]
            if s["name"] == "RUN_ON_STARTUP")
        self.assertIn("RunOnStartup", str(leak_setting["value"]),
                      f"the leak timer is not wired to the parameter: "
                      f"{leak_setting}")

    def test_both_timers_read_the_same_parameter(self):
        run_on_startup_lines = [line for line in BICEP.splitlines()
                               if "RUN_ON_STARTUP" in line]
        self.assertEqual(len(run_on_startup_lines), 2,
                         f"expected the leak and former settings, got "
                         f"{run_on_startup_lines}")
        for line in run_on_startup_lines:
            self.assertIn("RunOnStartup", line,
                          f"this one is not wired to the parameter: {line}")


class OneWorkspaceToQuery(unittest.TestCase):
    """Application Insights held the app's own traces while the audit tables
    sat in a workspace the template also created. Answering "the app says it
    did this, did it?" meant two query surfaces with no way to join them."""

    def test_application_insights_is_linked_to_the_workspace(self):
        self.assertIn("WorkspaceResourceId", BICEP)
        self.assertIn("WorkspaceResourceId: workspace.id", BICEP,
                      "linked to some other workspace, or not to the one this "
                      "template creates")


def _leak_conf(**over):
    conf = {
        "storage_account_name": "sa",
        "socradar_api_key": "k", "socradar_company_id": "330",
        "socradar_base_url": "https://example.invalid",
        "enable_user_lookup": True, "verified_domains": [],
        "enable_create_incident": False, "enable_resolve_alarm": False,
        "enable_ropc": False, "entra_action_mode": "plan",
        "entra_max_actions_per_run": 50, "security_group_id": "",
        "enable_revoke_session": False, "enable_add_to_group": False,
        "enable_remove_from_group": False, "enable_password_change": False,
        "enable_disable_account": False, "enable_enable_account": False,
        "enable_confirm_risky": False, "enable_force_mfa_reregistration": False,
        "initial_lookback_minutes": 43200, "initial_start_date": "2026-07-27",
        "max_pages_per_run": 50, "leak_ledger_retention_days": 90,
    }
    conf.update(over)
    return conf


if __name__ == "__main__":
    unittest.main()
