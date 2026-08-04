"""The hardening round driven by the external audit (AUDIT-CODEX-2026-08-01).

One rule underneath all of these: when the input is wrong or the bookkeeping
fails, the product must land on the side that changes nothing — a typo must not
arm an action, a broken counter must not open a gate, a mutation that could not
be recorded must not be repeated, and a budget that ran out must not retire the
work it did not do.
"""

import logging
import os
import sys
import unittest
from unittest import mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import test_import_path  # noqa: E402,F401  (installs the azure stubs)

REPO = Path(__file__).resolve().parents[2]


class ATypoNeverArmsAnAction(unittest.TestCase):
    """H-6: _bool used to fall back to the DEFAULT on an unrecognised value,
    and several mutation switches default to on — so ENABLE_REVOKE_SESSION set
    to 'disabled' left the action armed."""

    def _bool(self, value, default):
        from utils.config import _bool
        with mock.patch.dict(os.environ, {"X_FLAG": value}, clear=False):
            return _bool("X_FLAG", default)

    def test_unrecognised_value_reads_as_false_even_with_default_true(self):
        self.assertFalse(self._bool("disabled", True))
        self.assertFalse(self._bool("enabled", True))   # not a recognised truthy
        self.assertFalse(self._bool("yes please", True))

    def test_recognised_values_still_work(self):
        self.assertTrue(self._bool("true", False))
        self.assertTrue(self._bool("1", False))
        self.assertFalse(self._bool("off", True))

    def test_missing_value_keeps_the_default(self):
        from utils.config import _bool
        env = {k: v for k, v in os.environ.items() if k != "X_FLAG"}
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertTrue(_bool("X_FLAG", True))

    def test_a_broken_cap_closes_the_gate(self):
        """A typo in FORMER_MAX_REMOVALS used to silently mean 100, not 0."""
        from utils.config import _int
        with mock.patch.dict(os.environ, {"X_CAP": "hundred"}, clear=False):
            self.assertEqual(_int("X_CAP", 100, on_invalid=0), 0)
            # operational ints keep the old behaviour: fall back to the default
            self.assertEqual(_int("X_CAP", 60), 60)

    def test_the_mutation_caps_pass_the_flag(self):
        src = (REPO / "FunctionApp" / "utils" / "config.py").read_text(encoding="utf-8")
        for key in ("ENTRA_MAX_ACTIONS_PER_RUN", "FORMER_MAX_ADDS",
                    "FORMER_MAX_REMOVALS", "FORMER_MAX_REMOVAL_PERCENT"):
            line = next(l for l in src.splitlines() if f'"{key}"' in l)
            self.assertIn("on_invalid=0", line,
                          f"{key} is a mutation ceiling; a typo must close it")


class AnUnknownRulesetIsStrict(unittest.TestCase):
    """L-3: an unknown RULESET_MODE used to fall through to standard behaviour
    (disabled users sent to the former list)."""

    _ENV = {
        "STORAGE_ACCOUNT_NAME": "sa", "SOCRADAR_COMPANY_ID": "1",
        "SOCRADAR_API_KEY": "k", "OWN_TENANT_IDS": "t1",
        "ENTRA_CLIENT_ID": "c1d",
    }

    def _mode(self, value):
        from utils import config
        with mock.patch.dict(os.environ, dict(self._ENV, RULESET_MODE=value), clear=True):
            return config.load_former()["ruleset_mode"]

    def test_typo_lands_on_strict(self):
        self.assertEqual(self._mode("standrad"), "strict")

    def test_known_values_untouched(self):
        self.assertEqual(self._mode("standard"), "standard")
        self.assertEqual(self._mode("strict"), "strict")
        self.assertEqual(self._mode("standart"), "standard")  # legacy spelling


class ACappedRunHoldsItsWindow(unittest.TestCase):
    """H-5: the ceiling used to let the checkpoint advance, retiring the
    actions it had deliberately not taken — while the README promised they
    were 'left for the next run'."""

    def test_capped_is_in_the_hold_expression(self):
        src = (REPO / "FunctionApp" / "function_app.py").read_text(encoding="utf-8")
        start = src.find("hold_checkpoint = (")
        expr = src[start:src.find(")", start) + 1]
        self.assertIn("capped", expr,
                      "a capped run must re-read its window so the remaining "
                      "actions get their turn")

    def test_a_capped_run_does_not_save_a_new_checkpoint(self):
        import time
        import function_app as fa
        conf = {
            "storage_account_name": "sa", "enable_user_lookup": True,
            "verified_domains": [], "enable_create_incident": False,
            "enable_resolve_alarm": False, "socradar_api_key": "k",
            "socradar_company_id": "1", "entra_action_mode": "apply",
            "entra_max_actions_per_run": 1,
            "enable_revoke_session": True, "enable_add_to_group": False,
            "enable_remove_from_group": False, "enable_password_change": False,
            "enable_disable_account": False, "enable_enable_account": False,
            "enable_confirm_risky": False,
            "enable_force_mfa_reregistration": False, "security_group_id": "",
            "enable_ropc": False, "socradar_base_url": "https://x.example",
            "initial_lookback_minutes": 43200, "initial_start_date": "",
            "client_id": "",
        }
        rows = [{"email": f"u{i}@x.com"} for i in range(3)]
        rows[-1]["_checkpoint_update"] = {"last_start_date": "2026-08-02"}
        saves = []
        ledger = mock.Mock()
        ledger.already_applied.return_value = False
        with mock.patch.object(fa.src_botnet, "fetch", return_value=rows), \
             mock.patch.object(fa.cp, "load", return_value={}), \
             mock.patch.object(fa.cp, "save",
                               side_effect=lambda *a: saves.append(a[-1])), \
             mock.patch.object(fa.law, "write_records", return_value=True), \
             mock.patch.object(fa.law, "write_lifecycle_event"), \
             mock.patch.object(fa.ledger_mod, "ActionLedger", return_value=ledger), \
             mock.patch.object(fa.entra, "lookup_user",
                               return_value=({"id": "x", "accountEnabled": True}, 200)), \
             mock.patch.object(fa.entra, "revoke_sessions", return_value=True):
            audit = fa._process_source("botnet", conf, None,
                                       {"t1": {"Authorization": "b"}},
                                       deadline=time.time() + 3600,
                                       checkpoint_key="botnet:1")
        self.assertTrue(audit["capped"])
        held = [s for s in saves if "consecutive_holds" in s and s.get("consecutive_holds", 0) > 0]
        advanced = [s for s in saves if s.get("last_start_date") == "2026-08-02"
                    and s.get("consecutive_holds", 1) == 0]
        self.assertTrue(held, f"the window was not held: saves={saves}")
        self.assertFalse(advanced, f"the window advanced past untaken actions: saves={saves}")


class AnUnrecordedActionIsNotAHeldWindow(unittest.TestCase):
    """H-4 (atomicity half): a ledger write that raised AFTER a successful
    Graph action used to count as a processing failure, hold the window, and
    the re-read then repeated the action — the ledger had no memory of it.
    Absorbing the failure and advancing is the cheaper mistake."""

    def test_the_failure_is_absorbed_and_tagged(self):
        import function_app as fa
        ledger = mock.Mock()
        ledger.record_applied.side_effect = RuntimeError("503")
        taken = []
        ok = fa._record_applied_safely(ledger, "a@x.com", "botnet",
                                       "revoke_session", "2026-08-01", taken)
        self.assertFalse(ok)
        self.assertEqual(taken, ["revoke_session_unrecorded"])
        self.assertEqual(ledger.record_applied.call_count, 2, "one retry, then absorb")

    def test_a_transient_failure_recovers_on_the_retry(self):
        import function_app as fa
        ledger = mock.Mock()
        ledger.record_applied.side_effect = [RuntimeError("503"), None]
        taken = []
        ok = fa._record_applied_safely(ledger, "a@x.com", "botnet",
                                       "revoke_session", "2026-08-01", taken)
        self.assertTrue(ok)
        self.assertEqual(taken, [])

    def test_no_bare_record_applied_remains_on_the_action_paths(self):
        src = (REPO / "FunctionApp" / "function_app.py").read_text(encoding="utf-8")
        bare = [l.strip() for l in src.splitlines()
                if "ledger.record_applied(" in l and "_record_applied_safely" not in l
                and "def _record_applied_safely" not in l
                and not l.strip().startswith("#")]
        # the helper's own call is the single allowed site
        self.assertEqual(len(bare), 1,
                         f"an action path bypasses the safe recorder: {bare}")


class TheRedactorCleansWhatItActuallyLogs(unittest.TestCase):
    """M-3: only the format string was redacted; a secret arriving as an
    argument — an external API echoing a credential in an error body — went
    through untouched."""

    def _capture(self, msg, *args):
        from utils.logger import get_logger
        log = get_logger("botnet")
        with self.assertLogs("socradar.entra.botnet", level="ERROR") as captured:
            log.error(msg, *args)
        return "\n".join(captured.output)

    def test_a_secret_in_an_argument_is_redacted(self):
        out = self._capture("remote response: %s", "password=TopSecret123&x=1")
        self.assertNotIn("TopSecret123", out)
        self.assertIn("REDACTED", out)

    def test_a_secret_in_the_format_string_is_still_redacted(self):
        out = self._capture("token: abc123 password=Hunter2")
        self.assertNotIn("Hunter2", out)

    def test_a_bad_format_does_not_lose_the_line(self):
        out = self._capture("only one %s here", "a", "b")  # too many args
        self.assertIn("only one", out)


class ATenantHasExactlyOneOwner(unittest.TestCase):
    """M-1: two company rows claiming the same tenant would search one
    directory for both companies and act in it for both. The portal grid
    cannot prevent it (its regex checks GUID shape per cell, not uniqueness)."""

    def test_a_contested_tenant_drops_every_claimant_loudly(self):
        from actions.former_companies import parse_company_map
        raw = ('[{"companyId":"A","tenantIds":"11111111-1111-1111-1111-111111111111","apiKey":"k"},'
               ' {"companyId":"B","tenantIds":"11111111-1111-1111-1111-111111111111","apiKey":"k"},'
               ' {"companyId":"C","tenantIds":"22222222-2222-2222-2222-222222222222","apiKey":"k"}]')
        rows, errors = parse_company_map(raw, {})
        self.assertEqual([r["company_id"] for r in rows], ["C"],
                         "both claimants must be dropped; picking a winner "
                         "guesses at ownership")
        self.assertTrue(any("claimed by companies" in e for e in errors))

    def test_case_difference_does_not_hide_the_conflict(self):
        from actions.former_companies import parse_company_map
        raw = ('[{"companyId":"A","tenantIds":"AAAAAAAA-1111-1111-1111-111111111111","apiKey":"k"},'
               ' {"companyId":"B","tenantIds":"aaaaaaaa-1111-1111-1111-111111111111","apiKey":"k"}]')
        rows, _ = parse_company_map(raw, {})
        self.assertEqual(rows, [])


class RowKeysCannotCollide(unittest.TestCase):
    """L-2: the old escape ('/'->'_') mapped different addresses onto the same
    row, so in mock mode one address could overwrite or delete another."""

    def test_the_old_collision_pair_now_differs(self):
        from actions.socradar_former import _email_row_key
        self.assertNotEqual(_email_row_key("a/b@example.com"),
                            _email_row_key("a_b@example.com"))

    def test_the_key_is_a_digest_not_an_escape(self):
        from actions.socradar_former import _email_row_key
        key = _email_row_key("person@example.com")
        self.assertEqual(len(key), 64)
        int(key, 16)  # raises if not hex


class TheTemplateTextsMatchTheCode(unittest.TestCase):
    """M-8: the bicep description and the portal tooltip both said 'per run'
    while the ceiling is per company per source; the group-tenant tooltip said
    removals-only while an incomplete snapshot stops everything."""

    def test_the_ceiling_description_says_per_company_per_source(self):
        bicep = (REPO / "deploy" / "main.bicep").read_text(encoding="utf-8")
        line = next(l for l in bicep.splitlines() if "Ceiling on account changes" in l)
        self.assertIn("per company per source", line)

    def test_the_form_tooltips_are_corrected(self):
        import json
        ui = json.dumps(json.loads(
            (REPO / "deploy" / "createUiDefinition.json").read_text(encoding="utf-8")))
        self.assertIn("per company per source", ui)
        self.assertIn("additions included", ui)
        self.assertNotIn("A ceiling for the whole run", ui)

    def test_the_contributor_role_is_conditional(self):
        import json
        arm = json.loads((REPO / "deploy" / "azuredeploy.json").read_text(encoding="utf-8"))
        resources = arm["resources"]
        pool = resources.values() if isinstance(resources, dict) else resources
        role = next(r for r in pool
                    if r.get("type") == "Microsoft.Authorization/roleAssignments"
                    and "de139f84" in json.dumps(r))
        # Not just "a condition exists" — a hardcoded false would pass that.
        # The role must live and die with the restart script that needs it.
        cond = role.get("condition", "")
        self.assertIn("RunOnStartup", cond)
        self.assertIn("PackageUri", cond)
        script = next(r for r in pool
                      if r.get("type") == "Microsoft.Resources/deploymentScripts"
                      and "triggerFirstRun" in json.dumps(r.get("name", "")))
        self.assertEqual(cond, script.get("condition"),
                         "the role's condition must be exactly the script's")

    def test_the_beta_graph_host_is_gone(self):
        src = (REPO / "FunctionApp" / "actions" / "entra_id.py").read_text(encoding="utf-8")
        self.assertNotIn("graph.microsoft.com/beta", src)
        self.assertIn("identityProtection/riskyUsers/confirmCompromised", src)


class ACappedPlanRunStillMakesProgress(unittest.TestCase):
    """The adversarial review of the capped-hold fix: plan mode records
    nothing in the ledger, so a held window replans the same people at the
    same point forever — five runs of churn ending in a false 'abandoned'
    event. Same for a zero cap (the typo-closed gate). Holding is only useful
    where a re-read can do new work: apply mode with a real budget."""

    def _run(self, mode, cap):
        import time
        import function_app as fa
        conf = {
            "storage_account_name": "sa", "enable_user_lookup": True,
            "verified_domains": [], "enable_create_incident": False,
            "enable_resolve_alarm": False, "socradar_api_key": "k",
            "socradar_company_id": "1", "entra_action_mode": mode,
            "entra_max_actions_per_run": cap,
            "enable_revoke_session": True, "enable_add_to_group": False,
            "enable_remove_from_group": False, "enable_password_change": False,
            "enable_disable_account": False, "enable_enable_account": False,
            "enable_confirm_risky": False,
            "enable_force_mfa_reregistration": False, "security_group_id": "",
            "enable_ropc": False, "socradar_base_url": "https://x.example",
            "initial_lookback_minutes": 43200, "initial_start_date": "",
            "client_id": "",
        }
        rows = [{"email": f"u{i}@x.com"} for i in range(3)]
        rows[-1]["_checkpoint_update"] = {"last_start_date": "2026-08-02"}
        saves = []
        ledger = mock.Mock()
        ledger.already_applied.return_value = False
        with mock.patch.object(fa.src_botnet, "fetch", return_value=rows), \
             mock.patch.object(fa.cp, "load", return_value={}), \
             mock.patch.object(fa.cp, "save",
                               side_effect=lambda *a: saves.append(a[-1])), \
             mock.patch.object(fa.law, "write_records", return_value=True), \
             mock.patch.object(fa.law, "write_lifecycle_event"), \
             mock.patch.object(fa.ledger_mod, "ActionLedger", return_value=ledger), \
             mock.patch.object(fa.entra, "lookup_user",
                               return_value=({"id": "x", "accountEnabled": True}, 200)), \
             mock.patch.object(fa.entra, "revoke_sessions", return_value=True):
            audit = fa._process_source("botnet", conf, None,
                                       {"t1": {"Authorization": "b"}},
                                       deadline=time.time() + 3600,
                                       checkpoint_key="botnet:1")
        return audit, saves

    def test_plan_mode_advances_despite_the_ceiling(self):
        audit, saves = self._run("plan", 1)
        self.assertTrue(audit["capped"])
        advanced = [s for s in saves if s.get("last_start_date") == "2026-08-02"]
        self.assertTrue(advanced,
                        "a plan run cannot make progress by re-reading; "
                        "holding it is pure churn ending in a false abandon")

    def test_a_zero_cap_advances_too(self):
        audit, saves = self._run("apply", 0)
        self.assertTrue(audit["capped"])
        advanced = [s for s in saves if s.get("last_start_date") == "2026-08-02"]
        self.assertTrue(advanced,
                        "a closed gate stays closed on the re-read; "
                        "holding for it is the same livelock")


class ABrokenMapNeverFallsBackToTheLegacyRow(unittest.TestCase):
    """The contested-tenant drop created a new path: a map whose rows all
    dropped used to fall through to the legacy scalar row — quietly
    retargeting the run at a company and tenant the operator never named.
    Configured-but-broken must stop, not redirect."""

    _CONTESTED = ('[{"companyId":"111","tenantIds":"aaaaaaaa-1111-1111-1111-111111111111","apiKey":"k"},'
                  ' {"companyId":"222","tenantIds":"aaaaaaaa-1111-1111-1111-111111111111","apiKey":"k"}]')

    def _fconf(self, map_raw):
        return {
            "company_map_raw": map_raw, "group_tenant_ids": [],
            "storage_account_name": "sa", "socradar_company_id": "999",
            "socradar_api_key": "legacy-key", "former_actor_email": "a@x.com",
            "own_tenant_ids": ["cccccccc-1111-1111-1111-111111111111"],
            "former_client_mode": "mock", "former_apply_changes": False,
            "enable_former_sync": True, "enable_cross_tenant_suppress": True,
            "include_deleted_users": True, "ruleset_mode": "standard",
            "former_guard_accept_drop": False, "former_guard_drop_percent": 50,
            "former_max_adds": 500, "former_max_removals": 100,
            "former_max_removal_percent": 50, "former_run_on_startup": False,
        }

    def test_the_timer_path_stops_loudly(self):
        import function_app as fa
        events = []
        with mock.patch.object(fa.law, "write_lifecycle_event",
                               side_effect=lambda c, e, **k: events.append(e)):
            run = fa._former_company_snapshots(self._fconf(self._CONTESTED), None,
                                               persist_baseline=False)
        self.assertEqual(run["topology"], "invalid-map")
        self.assertEqual(run["snaps"], [], "no snapshot may run on a broken map")
        self.assertIn("former_company_map_invalid", events)

    def test_no_map_at_all_still_uses_the_legacy_row(self):
        import function_app as fa
        with mock.patch.object(fa, "_prefetch_tenant_data", return_value={}), \
             mock.patch.object(fa.law, "write_lifecycle_event"):
            run = fa._former_company_snapshots(self._fconf(""), None,
                                               persist_baseline=False)
        self.assertEqual(run["topology"], "legacy")

    def test_the_manual_write_endpoint_refuses(self):
        import json
        import function_app as fa
        req = mock.Mock()
        req.get_json.return_value = {"action": "add",
                                     "emails": ["x@y.com"], "company_id": "111"}
        with mock.patch.object(fa.cfg, "load_former",
                               return_value=self._fconf(self._CONTESTED)):
            resp = fa.former_manual(req)
        self.assertEqual(resp.status_code, 409)
        body = json.loads(resp.get_body().decode())
        self.assertIn("no usable rows", body["error"])


class ALegacyKeyedRowStaysRemovable(unittest.TestCase):
    """The hash-key change alone made rows written under the old escape
    un-deletable: the delete missed, its not-found was swallowed, and the
    sync's union re-added the address forever. Both key schemes are tried."""

    class _Table:
        def __init__(self):
            self.rows = {}

        def upsert_entity(self, entity):
            self.rows[(entity["PartitionKey"], entity["RowKey"])] = dict(entity)

        def delete_entity(self, partition_key, row_key):
            from azure.core.exceptions import ResourceNotFoundError
            try:
                del self.rows[(partition_key, row_key)]
            except KeyError:
                raise ResourceNotFoundError("no row")

    def test_a_row_under_the_old_scheme_is_deleted(self):
        from actions.socradar_former import (_delete_email_row,
                                             _legacy_email_row_key)
        table = self._Table()
        table.rows[("330", _legacy_email_row_key("leaver@corp.com"))] = {
            "email": "leaver@corp.com"}
        self.assertTrue(_delete_email_row(table, "330", "leaver@corp.com"))
        self.assertEqual(table.rows, {})

    def test_a_row_under_the_new_scheme_is_deleted(self):
        from actions.socradar_former import _delete_email_row, _email_row_key
        table = self._Table()
        table.rows[("330", _email_row_key("leaver@corp.com"))] = {
            "email": "leaver@corp.com"}
        self.assertTrue(_delete_email_row(table, "330", "leaver@corp.com"))
        self.assertEqual(table.rows, {})

    def test_absence_is_reported_as_absence(self):
        from actions.socradar_former import _delete_email_row
        self.assertFalse(_delete_email_row(self._Table(), "330", "gone@x.com"))


if __name__ == "__main__":
    unittest.main()
