"""
Topology 2 (multi-company) tests: FORMER_COMPANY_MAP parsing, full-mesh group
derivation, per-company composition, and the per-row effective-apply decision.
Semantics must match the manager's Vodafone example (company A 330/te330,
B 440/te440, C 550/te550 in one deployment).
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from actions.former_companies import (
    parse_company_map, legacy_row, derive_group_tenants, all_tenants,
    company_effective_apply, compose_company)


VODAFONE = """[
  {"company_id": "330", "own_tenants": ["te330"], "api_key": "k330", "actor_email": "A@x.com"},
  {"company_id": "440", "own_tenants": ["te440"], "api_key": "k440", "actor_email": "b@x.com"},
  {"company_id": "550", "own_tenants": ["te550"], "api_key": "k550", "actor_email": "f@x.com"}
]"""


def _tenant(active=(), disabled=(), deleted=(), read_ok=True, error=""):
    return {"active": set(active), "disabled": set(disabled),
            "deleted": set(deleted), "read_ok": read_ok, "error": error}


class ParseTests(unittest.TestCase):

    def test_vodafone_map_parses(self):
        rows, errors = parse_company_map(VODAFONE, {})
        self.assertEqual(errors, [])
        self.assertEqual([r["company_id"] for r in rows], ["330", "440", "550"])
        self.assertEqual(rows[0]["actor_email"], "a@x.com")  # lowercased

    def test_empty_and_bad_json(self):
        self.assertEqual(parse_company_map("", {}), ([], []))
        rows, errors = parse_company_map("{not json", {})
        self.assertEqual(rows, [])
        self.assertIn("not valid JSON", errors[0])
        rows, errors = parse_company_map('{"a": 1}', {})
        self.assertIn("JSON array", errors[0])

    def test_bad_rows_dropped_good_rows_survive(self):
        raw = ('[{"company_id": "330", "own_tenants": ["t1"], "api_key": "k"},'
               ' {"own_tenants": ["t2"]},'
               ' {"company_id": "440"},'
               ' {"company_id": "330", "own_tenants": ["t3"]}]')
        rows, errors = parse_company_map(raw, {})
        self.assertEqual([r["company_id"] for r in rows], ["330"])
        self.assertEqual(len(errors), 3)  # missing id, missing tenants, duplicate

    def test_api_key_setting_indirection(self):
        raw = '[{"company_id": "330", "own_tenants": ["t1"], "api_key_setting": "K330"}]'
        rows, errors = parse_company_map(raw, {"K330": "secret330"})
        self.assertEqual(rows[0]["api_key"], "secret330")
        self.assertEqual(errors, [])
        rows, errors = parse_company_map(raw, {})
        self.assertEqual(rows[0]["api_key"], "")
        self.assertIn("K330", errors[0])

    def test_arm_grid_aliases_and_csv_tenants(self):
        # createUiDefinition EditableGrid emits camelCase + CSV tenant strings.
        raw = ('[{"companyId": "330", "tenantIds": "te330, te331 ,te330",'
               '  "apiKey": "k330", "actorEmail": "A@x.com"}]')
        rows, errors = parse_company_map(raw, {})
        self.assertEqual(errors, [])
        self.assertEqual(rows[0]["company_id"], "330")
        self.assertEqual(rows[0]["own_tenants"], ["te330", "te331"])  # split+dedupe
        self.assertEqual(rows[0]["api_key"], "k330")
        self.assertEqual(rows[0]["actor_email"], "a@x.com")

    def test_unsafe_company_id_dropped(self):
        # Partition filters interpolate company_id — quoting chars are refused.
        raw = ('[{"company_id": "330\' or true", "own_tenants": ["t1"], "api_key": "k"},'
               ' {"company_id": "ok-330_A", "own_tenants": ["t2"], "api_key": "k"}]')
        rows, errors = parse_company_map(raw, {})
        self.assertEqual([r["company_id"] for r in rows], ["ok-330_A"])
        self.assertIn("unsafe characters", errors[0])

    def test_legacy_row_from_scalars(self):
        row = legacy_row({"socradar_company_id": "330", "own_tenant_ids": ["t1"],
                          "socradar_api_key": "k", "former_actor_email": "A@x.com"})
        self.assertEqual(row["company_id"], "330")
        self.assertEqual(row["actor_email"], "a@x.com")


class DeriveTests(unittest.TestCase):

    def test_full_mesh(self):
        rows, _ = parse_company_map(VODAFONE, {})
        groups = derive_group_tenants(rows)
        self.assertEqual(groups["330"], ["te440", "te550"])
        self.assertEqual(groups["440"], ["te330", "te550"])
        self.assertEqual(groups["550"], ["te330", "te440"])

    def test_legacy_group_added_everywhere_minus_own(self):
        rows, _ = parse_company_map(VODAFONE, {})
        groups = derive_group_tenants(rows, legacy_group=["teHOLDING", "te330"])
        self.assertIn("teHOLDING", groups["330"])
        self.assertNotIn("te330", groups["330"])   # own never in own group
        self.assertIn("te330", groups["440"])

    def test_single_row_derives_empty_mesh(self):
        rows, _ = parse_company_map(
            '[{"company_id": "330", "own_tenants": ["t1"], "api_key": "k"}]', {})
        self.assertEqual(derive_group_tenants(rows)["330"], [])

    def test_all_tenants_union(self):
        rows, _ = parse_company_map(VODAFONE, {})
        tenants, own_union = all_tenants(rows, ["teHOLDING"])
        self.assertEqual(tenants, ["te330", "te440", "te550", "teHOLDING"])
        self.assertEqual(own_union, {"te330", "te440", "te550"})
        self.assertNotIn("teHOLDING", own_union)  # pure group: actives only


class EffectiveApplyTests(unittest.TestCase):

    ROW = {"company_id": "330", "own_tenants": ["t"], "api_key": "k", "actor_email": "a@x.com"}

    def test_global_off_wins(self):
        self.assertEqual(company_effective_apply(self.ROW, "real", False), (False, None))

    def test_real_missing_actor_forces_plan_only(self):
        row = dict(self.ROW, actor_email="")
        apply_c, note = company_effective_apply(row, "real", True)
        self.assertFalse(apply_c)
        self.assertIn("actor_email missing", note)

    def test_real_missing_key_forces_plan_only(self):
        row = dict(self.ROW, api_key="")
        apply_c, note = company_effective_apply(row, "real", True)
        self.assertFalse(apply_c)

    def test_mock_mode_needs_no_credentials(self):
        row = dict(self.ROW, api_key="", actor_email="")
        self.assertEqual(company_effective_apply(row, "mock", True), (True, None))


class ComposeTests(unittest.TestCase):

    KW = dict(ruleset_mode="standart", include_deleted=True,
              enable_former_sync=True, enable_cross=True)
    ROW = {"company_id": "330", "own_tenants": ["te330"], "api_key": "k", "actor_email": "a@x.com"}

    def test_vodafone_semantics_for_330(self):
        tenant_data = {
            "te330": _tenant(active={"owner1@x.com", "staff1@x.com"},
                             disabled={"eski330@x.com"}),
            "te440": _tenant(active={"sib440@x.com"}),
            "te550": _tenant(active={"sib550@x.com"}),
        }
        desired, stats, populations = compose_company(
            self.ROW, ["te440", "te550"], tenant_data, **self.KW)
        self.assertEqual(desired, {"sib440@x.com", "sib550@x.com", "eski330@x.com"})
        self.assertTrue(stats["snapshot_complete"])
        self.assertEqual(stats["company_id"], "330")
        self.assertEqual(populations["sibling_active"], {"sib440@x.com", "sib550@x.com"})

    def test_safety_invariant_own_active_subtracted(self):
        tenant_data = {
            "te330": _tenant(active={"bob@x.com"}),
            "te440": _tenant(active={"bob@x.com"}),  # dual-role person
        }
        desired, _, _ = compose_company(self.ROW, ["te440"], tenant_data, **self.KW)
        self.assertEqual(desired, set())  # own active NEVER former

    def test_own_tenant_unread_raises(self):
        tenant_data = {"te330": _tenant(read_ok=False, error="boom")}
        with self.assertRaises(RuntimeError):
            compose_company(self.ROW, [], tenant_data, **self.KW)

    def test_group_tenant_unread_marks_incomplete(self):
        tenant_data = {"te330": _tenant(active={"a@x.com"}),
                       "te440": _tenant(read_ok=False)}
        _, stats, _ = compose_company(self.ROW, ["te440"], tenant_data, **self.KW)
        self.assertFalse(stats["snapshot_complete"])

    def test_strict_mode_routes_disabled_to_review(self):
        tenant_data = {"te330": _tenant(active=set(), disabled={"d@x.com"})}
        kw = dict(self.KW, ruleset_mode="strict")
        desired, stats, populations = compose_company(self.ROW, [], tenant_data, **kw)
        self.assertEqual(desired, set())
        self.assertEqual(stats["review_needed"], 1)
        self.assertEqual(populations["own_disabled"], set())


if __name__ == "__main__":
    unittest.main()
