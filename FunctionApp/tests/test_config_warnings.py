"""
Tests for config.py warnings (C4) and ruleset_mode alias normalization (D1).
"""
import logging
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from actions.former_companies import compose_company


# Minimal env required by config.load() — satisfies all required fields.
_LOAD_ENV = {
    "SOCRADAR_API_KEY": "test-key",
    "SOCRADAR_COMPANY_ID": "1",
    "ENTRA_TENANT_ID": "tid",
    "ENTRA_CLIENT_ID": "cid",
    "DCR_IMMUTABLE_ID": "dcr-id",
    "DCR_ENDPOINT": "https://dcr.example.com",
    "STORAGE_ACCOUNT_NAME": "sa",
}

# Minimal env required by config.load_former() — satisfies all required fields.
_LOAD_FORMER_ENV = {
    "ENTRA_TENANT_ID": "tid",
    "ENTRA_CLIENT_ID": "cid",
    "SOCRADAR_COMPANY_ID": "1",
    "STORAGE_ACCOUNT_NAME": "sa",
}


def _tenant(active=(), disabled=(), deleted=(), read_ok=True, error=""):
    return {"active": set(active), "disabled": set(disabled),
            "deleted": set(deleted), "read_ok": read_ok, "error": error}


class CredentialIsStoredAsDeliveredTest(unittest.TestCase):
    """Masked or clear is decided per company in the SOCRadar platform. This app
    stores what arrived; a second switch on this side could only disagree with
    the source, and an operator reading Log Analytics would not know which of
    the two to believe."""

    def _load(self, extra=None):
        env = dict(_LOAD_ENV)
        env.update(extra or {})
        with mock.patch.dict(os.environ, env, clear=True):
            from utils import config
            return config.load()

    def test_no_local_password_switch_remains(self):
        conf = self._load()
        self.assertNotIn("enable_log_plaintext_password", conf)

    def test_setting_the_old_variable_changes_nothing(self):
        """An upgraded deployment may still carry the retired app setting."""
        off = self._load({"ENABLE_LOG_PLAINTEXT_PASSWORD": "false"})
        on = self._load({"ENABLE_LOG_PLAINTEXT_PASSWORD": "true"})
        self.assertEqual(off, on)

    def test_a_clear_credential_reaches_the_record(self):
        from utils import sanitize
        fields = sanitize.build_law_password_fields(sanitize.sanitize_password("Yaz**2026!"))
        self.assertEqual(fields["password"], "Yaz**2026!")
        self.assertTrue(fields["is_plaintext"])
        self.assertNotIn("2026", fields["password_masked"])

    def test_a_masked_credential_reaches_the_record_unchanged(self):
        from utils import sanitize
        fields = sanitize.build_law_password_fields(sanitize.sanitize_password("a******3"))
        self.assertEqual(fields["password"], "a******3")
        self.assertFalse(fields["is_plaintext"])

    def test_an_absent_credential_writes_no_password_field(self):
        from utils import sanitize
        fields = sanitize.build_law_password_fields(sanitize.sanitize_password(""))
        self.assertNotIn("password", fields)
        self.assertFalse(fields["password_present"])


class RulesetModeAliasTest(unittest.TestCase):
    """The canonical spelling is 'standard'. 'standart' shipped in earlier
    releases and is still the value set in running installations, so it has to
    keep working — an upgrade must not quietly change what those deployments do.
    """

    def test_load_former_legacy_standart_is_accepted(self):
        env = dict(_LOAD_FORMER_ENV, RULESET_MODE="standart")
        with mock.patch.dict(os.environ, env, clear=True):
            from utils import config
            conf = config.load_former()
        self.assertEqual(conf["ruleset_mode"], "standard",
                         "a deployment still set to the old spelling must keep "
                         "the same behaviour after an upgrade")

    def test_load_former_standard_stays_standard(self):
        env = dict(_LOAD_FORMER_ENV, RULESET_MODE="standard")
        with mock.patch.dict(os.environ, env, clear=True):
            from utils import config
            conf = config.load_former()
        self.assertEqual(conf["ruleset_mode"], "standard")

    def test_load_former_strict_stays_strict(self):
        env = dict(_LOAD_FORMER_ENV, RULESET_MODE="strict")
        with mock.patch.dict(os.environ, env, clear=True):
            from utils import config
            conf = config.load_former()
        self.assertEqual(conf["ruleset_mode"], "strict")

    def test_load_former_default_is_standard(self):
        env = dict(_LOAD_FORMER_ENV)
        with mock.patch.dict(os.environ, env, clear=True):
            from utils import config
            conf = config.load_former()
        self.assertEqual(conf["ruleset_mode"], "standard")

    def test_the_run_never_sees_the_legacy_spelling(self):
        """compose_company does no fix-up, so the value reaching it must already
        be normalised. This is the seam the fix-up used to hide."""
        env = dict(_LOAD_FORMER_ENV, RULESET_MODE="standart")
        with mock.patch.dict(os.environ, env, clear=True):
            from utils import config
            conf = config.load_former()

        row = {"company_id": "330", "own_tenants": ["te330"],
               "api_key": "k", "actor_email": "a@x.com"}
        tenant_data = {
            "te330": _tenant(active={"active@x.com"}, disabled={"disabled@x.com"}),
        }
        kw = dict(include_deleted=True, enable_former_sync=True, enable_cross=False)

        # What the timer actually passes: conf["ruleset_mode"], not the raw env.
        desired_legacy, stats_legacy, _ = compose_company(
            row, [], tenant_data, ruleset_mode=conf["ruleset_mode"], **kw)
        desired_standard, stats_standard, _ = compose_company(
            row, [], tenant_data, ruleset_mode="standard", **kw)

        self.assertEqual(conf["ruleset_mode"], "standard")
        self.assertEqual(desired_legacy, desired_standard)
        self.assertEqual(stats_legacy["desired"], stats_standard["desired"])

    def test_compose_company_strict_differs_from_standard(self):
        """strict routes disabled users to review, not desired -- unlike standard."""
        row = {"company_id": "330", "own_tenants": ["te330"],
               "api_key": "k", "actor_email": "a@x.com"}
        tenant_data = {
            "te330": _tenant(active=set(), disabled={"disabled@x.com"}),
        }
        kw = dict(include_deleted=True, enable_former_sync=True, enable_cross=False)

        desired_standard, _, _ = compose_company(
            row, [], tenant_data, ruleset_mode="standard", **kw)
        desired_strict, stats_strict, _ = compose_company(
            row, [], tenant_data, ruleset_mode="strict", **kw)

        self.assertIn("disabled@x.com", desired_standard)
        self.assertNotIn("disabled@x.com", desired_strict)
        self.assertEqual(stats_strict["review_needed"], 1)

    def test_the_template_no_longer_offers_the_old_spelling(self):
        """New deployments must not be handed the Turkish spelling to pick."""
        import json
        from pathlib import Path
        arm = json.loads((Path(__file__).resolve().parents[2] / "deploy" /
                          "azuredeploy.json").read_text(encoding="utf-8"))
        p = arm["parameters"]["RulesetMode"]
        self.assertEqual(p["allowedValues"], ["standard", "strict"])
        self.assertEqual(p["defaultValue"], "standard")


if __name__ == "__main__":
    unittest.main()
