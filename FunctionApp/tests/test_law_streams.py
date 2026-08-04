"""LAW writes: separate streams, company attribution, schema agreement.

A stream that does not declare a column drops it and still reports success, so
these tests compare what the code sends against what the template declares.
"""

import json
import re
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from test_import_path import _ensure_azure_stub  # noqa: E402

_ensure_azure_stub()

from actions import law_writer  # noqa: E402

TEMPLATE = Path(__file__).resolve().parents[2] / "deploy" / "azuredeploy.json"


def _conf():
    return {
        "dcr_immutable_id": "dcr-1",
        "dcr_endpoint": "https://example.ingest.monitor.azure.com",
        "socradar_company_id": "330",
    }


class StreamRoutingTest(unittest.TestCase):
    def test_import_summary_uses_its_own_stream(self):
        with mock.patch.object(law_writer, "_upload", return_value=True) as up:
            law_writer.write_audit(_conf(), [{"source": "botnet", "company_id": "330",
                                              "total": 5, "duration": 1.0}])
        self.assertEqual(up.call_args[0][1], law_writer.IMPORT_AUDIT_STREAM)

    def test_former_summary_still_uses_the_former_stream(self):
        with mock.patch.object(law_writer, "_upload", return_value=True) as up:
            law_writer.write_former_audit(_conf(), [{"company_id": "330"}])
        self.assertEqual(up.call_args[0][1], law_writer.AUDIT_STREAM)

    def test_records_carry_company_id(self):
        with mock.patch.object(law_writer, "_upload", return_value=True) as up:
            law_writer.write_records(_conf(), "botnet", [{"email": "a@x.com"}])
        sent = up.call_args[0][2]
        self.assertEqual(sent[0]["company_id"], "330")


class SchemaAgreementTest(unittest.TestCase):
    """Every field the code sends must be declared by the matching stream."""

    @classmethod
    def setUpClass(cls):
        if not TEMPLATE.exists():
            raise unittest.SkipTest("compiled template not present")
        template = json.loads(TEMPLATE.read_text())
        variables = template.get("variables", {})

        def column_names(value):
            """Resolve a compiled column list: a literal, a variables() lookup,
            or a union() of both."""
            if isinstance(value, list):
                return {c["name"] for c in value if isinstance(c, dict)}
            if not isinstance(value, str):
                return set()
            ref = re.fullmatch(r"\[variables\('(\w+)'\)\]", value)
            if ref:
                return column_names(variables.get(ref.group(1)))
            merged = re.fullmatch(r"\[union\((.*)\)\]", value, re.S)
            if merged:
                body = merged.group(1)
                names = set()
                for part in re.findall(r"variables\('(\w+)'\)", body):
                    names |= column_names(variables.get(part))
                # createObject('name', 'x', 'type', 'string')
                names |= set(re.findall(r"createObject\('name',\s*'(\w+)'", body))
                return names
            return set()

        resources = template["resources"]
        resources = resources.values() if isinstance(resources, dict) else resources
        dcr = next(r for r in resources
                   if isinstance(r, dict) and "dataCollectionRules" in str(r.get("type", "")))
        cls.declared = {
            stream: column_names(decl.get("columns"))
            for stream, decl in dcr["properties"]["streamDeclarations"].items()
        }

    def test_import_summary_fields_are_declared(self):
        stream = law_writer.IMPORT_AUDIT_STREAM
        self.assertIn(stream, self.declared, "template declares no import audit stream")

        with mock.patch.object(law_writer, "_upload", return_value=True) as up:
            law_writer.write_audit(_conf(), [{
                "source": "botnet", "company_id": "330", "total": 1, "employees": 1,
                "found": 1, "not_found": 0, "actions": 2, "errors": 0,
                "domain_filtered": 0, "capped": True, "duration": 1.5,
            }])
        sent = set(up.call_args[0][2][0])
        self.assertEqual(sent - self.declared[stream], set(),
                         "fields would be dropped silently by the ingestion API")

    def _fields_the_code_really_sends(self, source):
        """Drive the actual import path and capture what reaches the uploader.

        Hand-written records only prove what the test author remembered. The
        VIP stream lost two columns for exactly that reason: the response path
        adds MFA counters regardless of which feed matched, and no hand-built
        botnet record ever exercised it.
        """
        import function_app

        employees = [{
            "email": "a@x.com", "company_id": "330", "source": source,
            "is_employee": True, "alarm_id": 1,
            "password_present": True, "password_masked": "a***3",
            "is_plaintext": False,
            "_checkpoint_update": {"last_start_date": "2026-07-27"},
        }]
        conf = {
            # Without these the writer logs and returns False, and the test
            # would pass by never reaching the uploader at all.
            "dcr_immutable_id": "dcr-1",
            "dcr_endpoint": "https://example.ingest.monitor.azure.com",
            "socradar_company_id": "330", "socradar_api_key": "k",
            "socradar_base_url": "https://example.invalid",
            "storage_account_name": "sa", "tenant_ids": ["t-a"], "tenant_id": "",
            "client_id": "app-1", "enable_user_lookup": True, "verified_domains": [],
            "entra_action_mode": "apply", "entra_max_actions_per_run": 50,
            "enable_revoke_session": False, "enable_add_to_group": False,
            "enable_remove_from_group": False, "enable_password_change": False,
            "enable_disable_account": False, "enable_enable_account": False,
            "enable_confirm_risky": False, "enable_force_mfa_reregistration": True,
            "enable_create_incident": False, "enable_resolve_alarm": False,
            "enable_ropc": False, "security_group_id": "",
            "initial_lookback_minutes": 43200, "initial_start_date": "",
            "max_pages_per_run": 50,
        }
        fetcher = {"botnet": function_app.src_botnet,
                   "pii": function_app.src_pii,
                   "vip": function_app.src_vip}[source]

        from actions.action_ledger import InMemoryActionLedger
        with mock.patch.object(fetcher, "fetch", return_value=employees), \
             mock.patch.object(function_app.cp, "load", return_value={}), \
             mock.patch.object(function_app.cp, "save"), \
             mock.patch.object(function_app.entra, "lookup_user",
                               return_value=({"id": "u1", "accountEnabled": True}, 200)), \
             mock.patch.object(function_app.entra, "force_mfa_reregistration",
                               return_value={"methods_deleted": 1, "methods_skipped": 1,
                                             "permission_denied": False, "errors": []}), \
             mock.patch.object(function_app.ledger_mod, "ActionLedger",
                               return_value=InMemoryActionLedger()), \
             mock.patch.object(law_writer, "_upload", return_value=True) as up:
            function_app._process_source(
                source, conf, None, {"t-a": {"Authorization": "x"}},
                deadline=float("inf"), checkpoint_key=f"{source}:330")

        calls = [c for c in up.call_args_list if c[0][1] == law_writer.STREAM_MAP[source]]
        self.assertTrue(calls, f"no {source} record reached the uploader")
        return set(calls[0][0][2][0])

    def test_botnet_record_fields_are_declared(self):
        sent = self._fields_the_code_really_sends("botnet")
        stream = law_writer.STREAM_MAP["botnet"]
        self.assertEqual(sent - self.declared[stream], set(),
                         "fields would be dropped silently by the ingestion API")

    def test_pii_record_fields_are_declared(self):
        sent = self._fields_the_code_really_sends("pii")
        stream = law_writer.STREAM_MAP["pii"]
        self.assertEqual(sent - self.declared[stream], set(),
                         "fields would be dropped silently by the ingestion API")

    def test_vip_record_fields_are_declared(self):
        sent = self._fields_the_code_really_sends("vip")
        stream = law_writer.STREAM_MAP["vip"]
        self.assertEqual(sent - self.declared[stream], set(),
                         "fields would be dropped silently by the ingestion API")

    def test_lifecycle_event_fields_are_declared(self):
        """consent_revoked carries a diagnostic code that used to vanish."""
        stream = law_writer.AUDIT_STREAM
        with mock.patch.object(law_writer, "_upload", return_value=True) as up:
            law_writer.write_lifecycle_event(
                _conf(), event_type="consent_revoked", tenant_id="t-a",
                details="token failed", extra={"aadsts_code": "AADSTS700213"})
        sent = set(up.call_args[0][2][0])
        self.assertEqual(sent - self.declared[stream], set(),
                         "fields would be dropped silently by the ingestion API")


if __name__ == "__main__":
    unittest.main()
