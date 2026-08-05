"""A tenant we could not read has to say so where the answer survives.

Both cases here end the run the same way: the snapshot is incomplete and no
mutation happens. That is correct, and it is also why they were invisible —
one phrase, `incomplete_snapshot`, stood for revoked consent, a missing
federated credential, exhausted throttling and a network fault alike. The log
line named the cause and then aged out.
"""

import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import test_import_path  # noqa: E402,F401  (installs the azure stubs)
import function_app  # noqa: E402
from actions import law_writer  # noqa: E402


def _fconf(**over):
    conf = {
        "client_id": "cid", "enable_former_sync": True,
        "include_deleted_users": True, "socradar_company_id": "1",
        "dcr_immutable_id": "rule", "dcr_endpoint": "https://dce.test",
    }
    conf.update(over)
    return conf


class ATenantThatCouldNotBeRead(unittest.TestCase):
    """The group tenant read path swallowed the reason. It no longer does."""

    def _run(self, err):
        with mock.patch.object(function_app.entra, "get_graph_token", side_effect=err), \
             mock.patch.object(function_app.law, "write_lifecycle_event") as event:
            data = function_app._prefetch_tenant_data(
                _fconf(), ["dddddddd-0000-0000-0000-000000000000"], set())
        return data, event

    def test_the_failure_is_still_recorded_on_the_entry(self):
        data, _ = self._run(RuntimeError("consent revoked"))
        entry = data["dddddddd-0000-0000-0000-000000000000"]
        self.assertFalse(entry["read_ok"])
        self.assertIn("consent revoked", entry["error"])

    def test_it_reaches_the_persistent_audit_trail(self):
        _, event = self._run(RuntimeError("consent revoked"))
        self.assertTrue(
            event.called,
            "the only trace was a log line; the audit table showed nothing but "
            "incomplete_snapshot, which names no cause")
        self.assertEqual(event.call_args.args[1], "former_tenant_read_failed")

    def test_the_reason_travels_with_it(self):
        _, event = self._run(RuntimeError("AADSTS70021 no matching federated identity"))
        details = event.call_args.kwargs.get("details", "")
        self.assertIn("AADSTS70021", details,
                      "without the reason the row cannot tell a revoked consent "
                      "from a missing credential")

    def test_the_tenant_is_named(self):
        _, event = self._run(RuntimeError("boom"))
        self.assertEqual(event.call_args.kwargs.get("tenant_id"),
                         "dddddddd-0000-0000-0000-000000000000")

    def test_a_tenant_that_reads_fine_stays_quiet(self):
        with mock.patch.object(function_app.entra, "get_graph_token", return_value="t"), \
             mock.patch.object(function_app.src_users, "get_active_members", return_value=[]), \
             mock.patch.object(function_app.src_users, "get_disabled_members", return_value=[]), \
             mock.patch.object(function_app.src_users, "get_deleted_members", return_value=[]), \
             mock.patch.object(function_app.law, "write_lifecycle_event") as event:
            data = function_app._prefetch_tenant_data(_fconf(), ["t1"], set())
        self.assertTrue(data["t1"]["read_ok"])
        self.assertFalse(event.called)

    def test_a_failing_audit_write_does_not_take_the_run_down(self):
        with mock.patch.object(function_app.entra, "get_graph_token",
                               side_effect=RuntimeError("boom")), \
             mock.patch.object(function_app.law, "write_lifecycle_event",
                               side_effect=RuntimeError("DCR down")):
            data = function_app._prefetch_tenant_data(_fconf(), ["t1"], set())
        self.assertFalse(data["t1"]["read_ok"])  # the run continued


class WhichCompanyTheEventBelongsTo(unittest.TestCase):
    """A lifecycle row with no company is invisible to a per-company query."""

    def _record(self, conf):
        with mock.patch.object(law_writer, "_upload", return_value=True) as up:
            law_writer.write_lifecycle_event(conf, "former_tenant_read_failed",
                                             tenant_id="t1", details="why")
        return up.call_args.args[2][0]

    def test_the_company_is_on_the_row(self):
        row = self._record(_fconf())
        self.assertEqual(
            row["company_id"], "1",
            "a multi-company deployment filters this table by company; an empty "
            "value hides exactly the failures being investigated")

    def test_it_degrades_to_empty_rather_than_raising(self):
        conf = _fconf()
        conf.pop("socradar_company_id")
        row = self._record(conf)
        self.assertEqual(row["company_id"], "")

    def test_the_declared_schema_has_somewhere_to_put_it(self):
        import json
        template = (Path(__file__).resolve().parents[2] / "deploy" / "azuredeploy.json")
        doc = json.loads(template.read_text(encoding="utf-8"))
        columns = {c["name"] for c in doc["variables"]["auditColumns"]}
        self.assertIn("company_id", columns,
                      "an undeclared column is dropped by the rule without an error")


if __name__ == "__main__":
    unittest.main()
