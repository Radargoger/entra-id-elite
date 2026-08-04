"""Every way a record can leave the run must land in a named bucket.

The audit row's parts are supposed to add up to its total. They did not, and
the gap opened exactly when something went wrong: a lookup that failed with 403
or 5xx was counted in `errors` and nowhere else, so the equation broke in the
one case it exists to surface.

This file does not list the buckets by hand. It reads the exit paths out of the
source and drives each one, so a new path added later fails here instead of
silently widening the gap.
"""

import re
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import test_import_path  # noqa: E402,F401  (installs the azure stubs)
import function_app  # noqa: E402

REPO = Path(__file__).resolve().parents[2]

BUCKETS = ("found", "not_found", "no_address", "domain_filtered",
           "lookup_disabled", "no_token", "lookup_failed")


def _conf(**over):
    conf = {
        "storage_account_name": "sa", "enable_user_lookup": True,
        "verified_domains": [], "enable_create_incident": False,
        "enable_resolve_alarm": False, "socradar_api_key": "k",
        "socradar_company_id": "1", "entra_action_mode": "plan",
    }
    conf.update(over)
    return conf


def _rows(n=2):
    rows = [{"email": f"u{i}@example.com"} for i in range(n)]
    rows[-1]["_checkpoint_update"] = {"last_start_date": "2026-07-30"}
    return rows


def _run(conf, tenants, lookup=None):
    patches = [
        mock.patch.object(function_app.src_botnet, "fetch", return_value=_rows()),
        mock.patch.object(function_app.cp, "load", return_value={}),
        mock.patch.object(function_app.cp, "save"),
        mock.patch.object(function_app.law, "write_records"),
    ]
    if lookup is not None:
        patches.append(mock.patch.object(function_app.entra, "lookup_user",
                                         return_value=lookup))
    for p in patches:
        p.start()
    try:
        return function_app._process_source("botnet", conf, None, tenants,
                                            deadline=time.time() + 3600,
                                            checkpoint_key="botnet:1")
    finally:
        for p in reversed(patches):
            p.stop()


class TheAuditRowAddsUpOnEveryPath(unittest.TestCase):

    def _assert_closes(self, audit, path):
        parts = sum(audit[b] for b in BUCKETS)
        self.assertEqual(
            audit["total"], parts,
            f"{path}: {audit['total'] - parts} record(s) left with no bucket "
            f"({ {b: audit[b] for b in BUCKETS} })")

    def test_when_users_are_found(self):
        self._assert_closes(
            _run(_conf(), {"t1": {"Authorization": "b"}}, lookup=({"id": "x"}, 200)),
            "found")

    def test_when_users_are_not_found(self):
        self._assert_closes(
            _run(_conf(), {"t1": {"Authorization": "b"}}, lookup=(None, 404)),
            "not_found")

    def test_when_the_lookup_is_refused(self):
        self._assert_closes(
            _run(_conf(), {"t1": {"Authorization": "b"}}, lookup=(None, 403)),
            "lookup_permission_denied")

    def test_when_the_lookup_errors(self):
        self._assert_closes(
            _run(_conf(), {"t1": {"Authorization": "b"}}, lookup=(None, 500)),
            "lookup_failed")

    def test_when_no_token_was_available(self):
        self._assert_closes(_run(_conf(), {}), "skipped_no_token")

    def test_when_lookup_is_switched_off(self):
        self._assert_closes(_run(_conf(enable_user_lookup=False), {}),
                            "skipped_user_lookup_disabled")

    def test_when_the_domain_allowlist_rejects_everything(self):
        self._assert_closes(
            _run(_conf(verified_domains=["other.test"]), {"t1": {"Authorization": "b"}}),
            "skipped_domain_allowlist")

    def test_when_records_carry_no_address(self):
        rows = [{"email": ""}, {"email": ""}]
        rows[-1]["_checkpoint_update"] = {"last_start_date": "2026-07-30"}
        with mock.patch.object(function_app.src_botnet, "fetch", return_value=rows), \
             mock.patch.object(function_app.cp, "load", return_value={}), \
             mock.patch.object(function_app.cp, "save"), \
             mock.patch.object(function_app.law, "write_records"):
            audit = function_app._process_source(
                "botnet", _conf(), None, {}, deadline=time.time() + 3600,
                checkpoint_key="botnet:1")
        self._assert_closes(audit, "skipped_no_address")


class NoExitPathIsLeftUncounted(unittest.TestCase):
    """Read the statuses out of the source rather than trusting a hand list."""

    def test_every_entra_status_maps_to_a_bucket(self):
        src = (REPO / "FunctionApp" / "function_app.py").read_text(encoding="utf-8")
        start = src.find("def _process_source")
        body = src[start:src.find("\ndef ", start + 10)]
        statuses = set(re.findall(r'emp\["entra_status"\] = "([a-z_]+)"', body))
        known = {
            "found": "found", "compromised": "found", "not_found": "not_found",
            "skipped_no_address": "no_address",
            "skipped_domain_allowlist": "domain_filtered",
            "skipped_user_lookup_disabled": "lookup_disabled",
            "skipped_no_token": "no_token",
            "lookup_permission_denied": "lookup_failed",
            "lookup_failed": "lookup_failed",
        }
        unmapped = sorted(statuses - set(known))
        self.assertEqual(
            unmapped, [],
            f"these exit paths have no bucket, so the audit row will not add "
            f"up when they are taken: {unmapped}")


class TheCountersReachLogAnalytics(unittest.TestCase):
    """A bucket the collection rule does not declare is dropped in silence."""

    def test_every_bucket_has_a_declared_column(self):
        import json
        arm = json.loads((REPO / "deploy" / "azuredeploy.json").read_text(encoding="utf-8"))
        declared = {c["name"] for c in arm["variables"]["importAuditColumns"]}
        writer = (REPO / "FunctionApp" / "actions" / "law_writer.py").read_text(encoding="utf-8")
        block = writer.split("def write_audit")[1]
        written = set(re.findall(r'"([a-z_]+)":\s+r\.get\(', block))
        missing = sorted(written - declared)
        self.assertEqual(missing, [], f"uploaded but undeclared: {missing}")

    def test_lookup_failed_is_among_them(self):
        import json
        arm = json.loads((REPO / "deploy" / "azuredeploy.json").read_text(encoding="utf-8"))
        declared = {c["name"] for c in arm["variables"]["importAuditColumns"]}
        self.assertIn("lookup_failed_count", declared)


if __name__ == "__main__":
    unittest.main()
