"""
Topology 2 (multi-company) tests: FORMER_COMPANY_MAP parsing, full-mesh group
derivation, per-company composition, and the per-row effective-apply decision.
Semantics must match the manager's companydomain.com example (company A 1234567/te1234567,
B 440/te440, C 550/te550 in one deployment).
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from actions.former_companies import (
    parse_company_map, legacy_row, derive_group_tenants, all_tenants,
    company_effective_apply, compose_company)


COMPANYDOMAIN_MAP = """[
  {"company_id": "1234567", "own_tenants": ["te1234567"], "api_key": "k1234567", "actor_email": "A@x.com"},
  {"company_id": "440", "own_tenants": ["te440"], "api_key": "k440", "actor_email": "b@x.com"},
  {"company_id": "550", "own_tenants": ["te550"], "api_key": "k550", "actor_email": "f@x.com"}
]"""


def _tenant(active=(), disabled=(), deleted=(), read_ok=True, error=""):
    return {"active": set(active), "disabled": set(disabled),
            "deleted": set(deleted), "read_ok": read_ok, "error": error}


class ParseTests(unittest.TestCase):

    def test_companydomain_map_parses(self):
        rows, errors = parse_company_map(COMPANYDOMAIN_MAP, {})
        self.assertEqual(errors, [])
        self.assertEqual([r["company_id"] for r in rows], ["1234567", "440", "550"])
        self.assertEqual(rows[0]["actor_email"], "a@x.com")  # lowercased

    def test_empty_and_bad_json(self):
        self.assertEqual(parse_company_map("", {}), ([], []))
        rows, errors = parse_company_map("{not json", {})
        self.assertEqual(rows, [])
        self.assertIn("not valid JSON", errors[0])
        rows, errors = parse_company_map('{"a": 1}', {})
        self.assertIn("JSON array", errors[0])

    def test_bad_rows_dropped_good_rows_survive(self):
        raw = ('[{"company_id": "1234567", "own_tenants": ["t1"], "api_key": "k"},'
               ' {"own_tenants": ["t2"]},'
               ' {"company_id": "440"},'
               ' {"company_id": "1234567", "own_tenants": ["t3"]}]')
        rows, errors = parse_company_map(raw, {})
        self.assertEqual([r["company_id"] for r in rows], ["1234567"])
        self.assertEqual(len(errors), 3)  # missing id, missing tenants, duplicate

    def test_api_key_setting_indirection(self):
        raw = '[{"company_id": "1234567", "own_tenants": ["t1"], "api_key_setting": "K1234567"}]'
        rows, errors = parse_company_map(raw, {"K1234567": "secret1234567"})
        self.assertEqual(rows[0]["api_key"], "secret1234567")
        self.assertEqual(errors, [])
        rows, errors = parse_company_map(raw, {})
        self.assertEqual(rows[0]["api_key"], "")
        self.assertIn("K1234567", errors[0])

    def test_the_indirection_accepts_the_camelcase_spelling_too(self):
        """Every other field takes both spellings; this one did not, and the
        row that used the camelCase name kept no key and raised no error — the
        company was simply never read. The live deployment writes camelCase."""
        raw = ('[{"companyId": "1234567", "tenantIds": "t1",'
               '  "apiKeySetting": "K1234567", "actorEmail": "a@x.com"}]')
        rows, errors = parse_company_map(raw, {"K1234567": "secret1234567"})
        self.assertEqual(errors, [])
        self.assertEqual(rows[0]["api_key"], "secret1234567")

    def test_an_unresolvable_camelcase_reference_is_reported(self):
        raw = '[{"companyId": "1234567", "tenantIds": "t1", "apiKeySetting": "K1234567"}]'
        rows, errors = parse_company_map(raw, {})
        self.assertEqual(rows[0]["api_key"], "")
        self.assertTrue(any("K1234567" in e for e in errors),
                        "a reference that resolves to nothing has to say so")

    def test_arm_grid_aliases_and_csv_tenants(self):
        # createUiDefinition EditableGrid emits camelCase + CSV tenant strings.
        raw = ('[{"companyId": "1234567", "tenantIds": "te1234567, te331 ,te1234567",'
               '  "apiKey": "k1234567", "actorEmail": "A@x.com"}]')
        rows, errors = parse_company_map(raw, {})
        self.assertEqual(errors, [])
        self.assertEqual(rows[0]["company_id"], "1234567")
        self.assertEqual(rows[0]["own_tenants"], ["te1234567", "te331"])  # split+dedupe
        self.assertEqual(rows[0]["api_key"], "k1234567")
        self.assertEqual(rows[0]["actor_email"], "a@x.com")

    def test_unsafe_company_id_dropped(self):
        # Partition filters interpolate company_id — quoting chars are refused.
        raw = ('[{"company_id": "1234567\' or true", "own_tenants": ["t1"], "api_key": "k"},'
               ' {"company_id": "ok-1234567_A", "own_tenants": ["t2"], "api_key": "k"}]')
        rows, errors = parse_company_map(raw, {})
        self.assertEqual([r["company_id"] for r in rows], ["ok-1234567_A"])
        self.assertIn("unsafe characters", errors[0])

    def test_legacy_row_from_scalars(self):
        row = legacy_row({"socradar_company_id": "1234567", "own_tenant_ids": ["t1"],
                          "socradar_api_key": "k", "former_actor_email": "A@x.com"})
        self.assertEqual(row["company_id"], "1234567")
        self.assertEqual(row["actor_email"], "a@x.com")


class DeriveTests(unittest.TestCase):

    def test_full_mesh(self):
        rows, _ = parse_company_map(COMPANYDOMAIN_MAP, {})
        groups = derive_group_tenants(rows)
        self.assertEqual(groups["1234567"], ["te440", "te550"])
        self.assertEqual(groups["440"], ["te1234567", "te550"])
        self.assertEqual(groups["550"], ["te1234567", "te440"])

    def test_legacy_group_added_everywhere_minus_own(self):
        rows, _ = parse_company_map(COMPANYDOMAIN_MAP, {})
        groups = derive_group_tenants(rows, legacy_group=["teHOLDING", "te1234567"])
        self.assertIn("teHOLDING", groups["1234567"])
        self.assertNotIn("te1234567", groups["1234567"])   # own never in own group
        self.assertIn("te1234567", groups["440"])

    def test_single_row_derives_empty_mesh(self):
        rows, _ = parse_company_map(
            '[{"company_id": "1234567", "own_tenants": ["t1"], "api_key": "k"}]', {})
        self.assertEqual(derive_group_tenants(rows)["1234567"], [])

    def test_all_tenants_union(self):
        rows, _ = parse_company_map(COMPANYDOMAIN_MAP, {})
        tenants, own_union = all_tenants(rows, ["teHOLDING"])
        self.assertEqual(tenants, ["te1234567", "te440", "te550", "teHOLDING"])
        self.assertEqual(own_union, {"te1234567", "te440", "te550"})
        self.assertNotIn("teHOLDING", own_union)  # pure group: actives only


class EffectiveApplyTests(unittest.TestCase):

    ROW = {"company_id": "1234567", "own_tenants": ["t"], "api_key": "k", "actor_email": "a@x.com"}

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

    KW = dict(ruleset_mode="standard", include_deleted=True,
              enable_former_sync=True, enable_cross=True)
    ROW = {"company_id": "1234567", "own_tenants": ["te1234567"], "api_key": "k", "actor_email": "a@x.com"}

    def test_companydomain_semantics_for_1234567(self):
        tenant_data = {
            "te1234567": _tenant(active={"owner1@x.com", "staff1@x.com"},
                             disabled={"eski1234567@x.com"}),
            "te440": _tenant(active={"sib440@x.com"}),
            "te550": _tenant(active={"sib550@x.com"}),
        }
        desired, stats, populations = compose_company(
            self.ROW, ["te440", "te550"], tenant_data, **self.KW)
        self.assertEqual(desired, {"sib440@x.com", "sib550@x.com", "eski1234567@x.com"})
        self.assertTrue(stats["snapshot_complete"])
        self.assertEqual(stats["company_id"], "1234567")
        self.assertEqual(populations["sibling_active"], {"sib440@x.com", "sib550@x.com"})

    def test_safety_invariant_own_active_subtracted(self):
        tenant_data = {
            "te1234567": _tenant(active={"bob@x.com"}),
            "te440": _tenant(active={"bob@x.com"}),  # dual-role person
        }
        desired, _, _ = compose_company(self.ROW, ["te440"], tenant_data, **self.KW)
        self.assertEqual(desired, set())  # own active NEVER former

    def test_own_tenant_unread_raises(self):
        tenant_data = {"te1234567": _tenant(read_ok=False, error="boom")}
        with self.assertRaises(RuntimeError):
            compose_company(self.ROW, [], tenant_data, **self.KW)

    def test_group_tenant_unread_marks_incomplete(self):
        tenant_data = {"te1234567": _tenant(active={"a@x.com"}),
                       "te440": _tenant(read_ok=False)}
        _, stats, _ = compose_company(self.ROW, ["te440"], tenant_data, **self.KW)
        self.assertFalse(stats["snapshot_complete"])

    def test_strict_mode_routes_disabled_to_review(self):
        tenant_data = {"te1234567": _tenant(active=set(), disabled={"d@x.com"})}
        kw = dict(self.KW, ruleset_mode="strict")
        desired, stats, populations = compose_company(self.ROW, [], tenant_data, **kw)
        self.assertEqual(desired, set())
        self.assertEqual(stats["review_needed"], 1)
        self.assertEqual(populations["own_disabled"], set())


if __name__ == "__main__":
    unittest.main()
