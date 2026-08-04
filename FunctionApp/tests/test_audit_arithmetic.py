"""The import summary has to account for every record it counted.

`total` is the number of records the run handled. Each one then lands in exactly
one bucket: found in the directory, missed, filtered out by the domain
allowlist, or skipped because the record carried no address to look up. Until
the last of those had a counter, the buckets did not add up to the total and the
difference had no name — a reader could see 169 records handled and 0 found and
could not tell whether nobody matched or nobody was ever looked up.

The audit row is also checked against what the template declares, because a
column the collection rule does not declare is dropped on ingestion while the
upload still reports success.
"""

import json
import re
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from test_import_path import _ensure_azure_stub                 # noqa: E402

_ensure_azure_stub()

from actions import law_writer                                  # noqa: E402
import function_app                                             # noqa: E402

TEMPLATE = Path(__file__).resolve().parents[2] / "deploy" / "azuredeploy.json"


def _conf():
    return {
        "socradar_company_id": "1234567", "socradar_api_key": "k",
        "socradar_base_url": "https://example.invalid",
        "dcr_immutable_id": "dcr-1",
        "dcr_endpoint": "https://example.ingest.monitor.azure.com",
        "storage_account_name": "sa", "tenant_ids": ["t-a"], "tenant_id": "",
        "client_id": "app-1", "enable_user_lookup": True, "verified_domains": [],
        "entra_action_mode": "plan", "entra_max_actions_per_run": 50,
        "enable_revoke_session": False, "enable_add_to_group": False,
        "enable_remove_from_group": False, "enable_password_change": False,
        "enable_disable_account": False, "enable_enable_account": False,
        "enable_confirm_risky": False, "enable_force_mfa_reregistration": False,
        "enable_create_incident": False, "enable_resolve_alarm": False,
        "enable_ropc": False, "security_group_id": "",
        "initial_lookback_minutes": 43200, "initial_start_date": "",
        "max_pages_per_run": 50,
    }


def _employee(email, **over):
    rec = {
        "email": email, "company_id": "1234567", "source": "vip",
        "is_employee": True, "alarm_id": 1, "vip_name": "A Person",
        "password_present": False, "password_masked": None,
        "is_plaintext": False,
    }
    rec.update(over)
    return rec


def _run(employees, conf=None):
    conf = conf or _conf()
    employees = list(employees)
    employees[-1]["_checkpoint_update"] = {"last_start_date": "2026-07-27"}
    with mock.patch.object(function_app.src_vip, "fetch", return_value=employees), \
         mock.patch.object(function_app.cp, "load", return_value={}), \
         mock.patch.object(function_app.cp, "save"), \
         mock.patch.object(function_app.entra, "lookup_user",
                           side_effect=lambda addr, h: (
                               ({"id": "u1", "accountEnabled": True}, 200)
                               if addr.startswith("known") else (None, 404))), \
         mock.patch.object(law_writer, "_upload", return_value=True):
        return function_app._process_source(
            "vip", conf, None, {"t-a": {"Authorization": "x"}},
            deadline=float("inf"), checkpoint_key="vip:1234567")


def _walk(node):
    """Yield every dict in the template, whatever shape `resources` takes.

    Bicep emits resources as a map under symbolic names, and nested deployments
    bury their own resources further down. Iterating one assumed shape found
    nothing and would have passed a test that checks a declaration exists.
    """
    if isinstance(node, dict):
        yield node
        for v in node.values():
            yield from _walk(v)
    elif isinstance(node, list):
        for v in node:
            yield from _walk(v)


def _resolve(value, doc):
    """Resolve `[variables('x')]` to the literal the template defines.

    The table takes its columns through a variable while the stream declaration
    inlines them. Reading the unresolved string as a list of columns raised, and
    reading it as an empty list would have made this test pass on any template
    at all.
    """
    if isinstance(value, str):
        m = re.fullmatch(r"\[variables\('([^']+)'\)\]", value.strip())
        if m:
            return doc.get("variables", {}).get(m.group(1))
    return value


def _stream_columns():
    doc = json.loads(TEMPLATE.read_text())
    for node in _walk(doc):
        decls = node.get("streamDeclarations")
        if isinstance(decls, dict):
            entry = decls.get("Custom-SOCRadar_ImportAudit_CL")
            if isinstance(entry, dict):
                cols = _resolve(entry.get("columns"), doc)
                if isinstance(cols, list):
                    return {c["name"] for c in cols}
    return set()


def _table_columns():
    doc = json.loads(TEMPLATE.read_text())
    for node in _walk(doc):
        schema = node.get("schema")
        if isinstance(schema, dict) and schema.get("name") == "SOCRadar_ImportAudit_CL":
            cols = _resolve(schema.get("columns"), doc)
            if isinstance(cols, list):
                return {c["name"] for c in cols}
    return set()



class TheBucketsAddUpToTheTotal(unittest.TestCase):
    def test_a_skipped_record_is_counted(self):
        r = _run([_employee(""), _employee("")])
        self.assertEqual(r["no_address"], 2)

    def test_a_record_with_an_address_is_not_counted_as_skipped(self):
        # Guards the counter against being incremented for everything.
        r = _run([_employee("known@x.invalid")])
        self.assertEqual(r["no_address"], 0)
        self.assertEqual(r["found"], 1)

    def test_every_record_lands_in_exactly_one_bucket(self):
        r = _run([_employee("known@x.invalid"),
                  _employee("stranger@x.invalid"),
                  _employee(""), _employee("")])
        parts = r["found"] + r["not_found"] + r["domain_filtered"] + r["no_address"]
        self.assertEqual(
            parts, r["total"],
            f"{r['total']} records handled but {parts} accounted for",
        )

    def test_the_mix_is_split_the_way_it_happened(self):
        # The sum closing is not enough on its own: one bucket absorbing another
        # would still add up.
        r = _run([_employee("known@x.invalid"),
                  _employee("stranger@x.invalid"),
                  _employee("")])
        self.assertEqual((r["found"], r["not_found"], r["no_address"]), (1, 1, 1))


class TheCounterReachesLogAnalytics(unittest.TestCase):
    def _audit_row(self, result):
        with mock.patch.object(law_writer, "_upload", return_value=True) as up:
            law_writer.write_audit(_conf(), [result])
        self.assertTrue(up.called, "the audit summary never reached the uploader")
        return up.call_args[0][2][0]

    def test_the_row_carries_the_count(self):
        row = self._audit_row(_run([_employee(""), _employee("")]))
        self.assertEqual(row.get("no_address_count"), 2)

    def test_the_column_is_declared_in_the_template(self):
        # A column the collection rule does not declare is dropped on
        # ingestion, and the upload still reports success.
        cols = _stream_columns()
        self.assertTrue(cols, "the import-audit stream declaration was not found")
        self.assertIn("no_address_count", cols)

    def test_the_table_stores_it_too(self):
        # The stream and the table are declared separately; a column in one and
        # not the other still ends in silence.
        cols = _table_columns()
        self.assertTrue(cols, "the import-audit table was not found")
        self.assertIn("no_address_count", cols)

    def test_every_audit_field_the_code_sends_is_declared(self):
        # Broader than the one new column: nothing the writer emits may be
        # missing from the declaration.
        row = self._audit_row(_run([_employee("")]))
        self.assertEqual(set(row) - _stream_columns(), set(),
                         "these fields would be dropped silently on ingestion")


if __name__ == "__main__":
    unittest.main()
