"""Import path guarantees: tenant scoping, company isolation, action gates."""

import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from test_import_path import _ensure_azure_stub  # noqa: E402

_ensure_azure_stub()

import function_app  # noqa: E402


MAP = (
    '[{"companyId":"330","tenantIds":"t-330","apiKey":"k330","actorEmail":"a@x.com"},'
    ' {"companyId":"440","tenantIds":"t-440","apiKey":"k440","actorEmail":"b@x.com"}]'
)


def _conf(**over):
    conf = {
        "socradar_company_id": "legacy-1",
        "socradar_api_key": "legacy-key",
        "company_map_raw": "",
        "tenant_ids": ["t-global"],
        "tenant_id": "",
        "client_id": "app-1",
        "enable_user_lookup": True,
        "entra_action_mode": "plan",
        "entra_max_actions_per_run": 50,
    }
    conf.update(over)
    return conf


class TenantScopingTest(unittest.TestCase):
    """A company's leaked credentials may only be searched in that company's own
    tenants. The global ENTRA_TENANT_IDS must never leak into a mapped row."""

    def test_row_tenants_win_over_global(self):
        rows = function_app._import_company_rows(_conf(company_map_raw=MAP))
        self.assertEqual([r["company_id"] for r in rows], ["330", "440"])

        first = function_app._import_company_conf(_conf(company_map_raw=MAP), rows[0])
        second = function_app._import_company_conf(_conf(company_map_raw=MAP), rows[1])

        self.assertEqual(first["tenant_ids"], ["t-330"])
        self.assertEqual(second["tenant_ids"], ["t-440"])
        self.assertNotIn("t-global", first["tenant_ids"] + second["tenant_ids"])
        self.assertEqual(first["socradar_api_key"], "k330")
        self.assertEqual(second["socradar_api_key"], "k440")

    def test_tokens_requested_only_for_own_tenants(self):
        rows = function_app._import_company_rows(_conf(company_map_raw=MAP))
        ccfg = function_app._import_company_conf(_conf(company_map_raw=MAP), rows[0])

        asked = []
        with mock.patch.object(function_app.entra, "get_graph_token",
                               side_effect=lambda tenant_id, client_id: asked.append(tenant_id) or "tok"):
            headers = function_app._acquire_tenant_tokens(ccfg, "330")

        self.assertEqual(asked, ["t-330"])
        self.assertEqual(list(headers), ["t-330"])

    def test_legacy_deployment_keeps_global_tenants(self):
        rows = function_app._import_company_rows(_conf())
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]["_legacy"])
        self.assertEqual(rows[0]["own_tenants"], ["t-global"])

    def test_broken_map_fails_loudly(self):
        with self.assertRaises(RuntimeError):
            function_app._import_company_rows(_conf(company_map_raw="{not json"))


class CheckpointPartitionTest(unittest.TestCase):
    def test_companies_do_not_share_a_partition(self):
        row = {"company_id": "330"}
        self.assertEqual(function_app._checkpoint_key("botnet", "330", row), "botnet:330")
        self.assertNotEqual(
            function_app._checkpoint_key("botnet", "330", row),
            function_app._checkpoint_key("botnet", "440", {"company_id": "440"}),
        )

    def test_legacy_partition_unchanged(self):
        # An upgrade must not lose an existing deployment's place in the feed.
        self.assertEqual(
            function_app._checkpoint_key("botnet", "legacy-1", {"_legacy": True}), "botnet")


def _found_user(*_a, **_k):
    return {"id": "u-1", "accountEnabled": True}, 200


class ActionGateTest(unittest.TestCase):
    """Directory mutations pass two gates: the action mode and the run ceiling."""

    def _process(self, conf_over, records=3):
        employees = [{"email": f"u{i}@x.com"} for i in range(records)]
        employees[-1]["_checkpoint_update"] = {"last_start_date": "2026-07-27"}
        conf = _conf(**conf_over)
        conf.update({
            "storage_account_name": "sa", "verified_domains": [],
            "enable_revoke_session": True, "enable_disable_account": True,
            "enable_add_to_group": False, "enable_remove_from_group": False,
            "enable_password_change": False, "enable_enable_account": False,
            "enable_confirm_risky": False, "enable_force_mfa_reregistration": False,
            "enable_create_incident": False, "enable_resolve_alarm": False,
            "enable_ropc": False, "security_group_id": "",
        })
        headers = {"t-330": {"Authorization": "x"}}

        from actions.action_ledger import InMemoryActionLedger
        with mock.patch.object(function_app.src_botnet, "fetch", return_value=employees), \
             mock.patch.object(function_app.cp, "load", return_value={}), \
             mock.patch.object(function_app.cp, "save"), \
             mock.patch.object(function_app.law, "write_records") as write, \
             mock.patch.object(function_app.entra, "lookup_user", side_effect=_found_user), \
             mock.patch.object(function_app.entra, "revoke_sessions", return_value=True) as revoke, \
             mock.patch.object(function_app.entra, "disable_account", return_value=True) as disable, \
             mock.patch.object(function_app.ledger_mod, "ActionLedger",
                               return_value=InMemoryActionLedger()):
            result = function_app._process_source(
                "botnet", conf, None, headers,
                deadline=float("inf"), checkpoint_key="botnet:330")
        written = write.call_args[0][2] if write.call_args else []
        return result, revoke, disable, written

    def test_plan_mode_touches_nothing(self):
        result, revoke, disable, written = self._process({"entra_action_mode": "plan"})
        revoke.assert_not_called()
        disable.assert_not_called()
        self.assertEqual(result["actions"], 6)  # 3 records x 2 actions, all planned
        self.assertTrue(all(a.endswith("_planned") for a in written[0]["actions_taken"]))

    def test_apply_mode_calls_graph(self):
        _, revoke, disable, written = self._process({"entra_action_mode": "apply"})
        self.assertEqual(revoke.call_count, 3)
        self.assertEqual(disable.call_count, 3)
        self.assertIn("revoke_session", written[0]["actions_taken"])

    def test_ceiling_stops_mutations_midway(self):
        result, revoke, disable, written = self._process(
            {"entra_action_mode": "apply", "entra_max_actions_per_run": 3})
        self.assertEqual(revoke.call_count + disable.call_count, 3)
        self.assertTrue(result["capped"])
        self.assertIn("_skipped_cap", " ".join(written[-1]["actions_taken"]))


class FetchFailureTest(unittest.TestCase):
    def test_failed_fetch_is_an_error_not_an_empty_success(self):
        marker = [{"_checkpoint_update": {}, "_empty_marker": True, "_fetch_failed": True}]
        conf = _conf(enable_user_lookup=False)
        conf.update({"storage_account_name": "sa", "verified_domains": []})

        with mock.patch.object(function_app.src_botnet, "fetch", return_value=marker), \
             mock.patch.object(function_app.cp, "load", return_value={}), \
             mock.patch.object(function_app.cp, "save"), \
             mock.patch.object(function_app.law, "write_records"):
            result = function_app._process_source(
                "botnet", conf, None, {}, deadline=float("inf"), checkpoint_key="botnet:330")

        self.assertEqual(result["errors"], 1)
        self.assertEqual(result["total"], 0)
        self.assertEqual(result["employees"], 0)


if __name__ == "__main__":
    unittest.main()
