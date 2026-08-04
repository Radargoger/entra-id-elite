"""Leak probe: a company is searched in its own tenants and nowhere else."""

import json
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from test_import_path import _ensure_azure_stub  # noqa: E402

_ensure_azure_stub()

import function_app  # noqa: E402


MAP = json.dumps([
    {"companyId": "330", "tenantIds": "tenant-A", "apiKey": "kA", "actorEmail": "a@x.com"},
    {"companyId": "440", "tenantIds": "tenant-B", "apiKey": "kB", "actorEmail": "b@x.com"},
])

# Only tenant-A holds this person.
DIRECTORY = {"tenant-A": {"probe@x.com": {"id": "user-1", "accountEnabled": True}}}


class _Req:
    def __init__(self, body):
        self._body = body

    def get_json(self):
        return self._body


def _env(**over):
    env = {
        "FORMER_COMPANY_MAP": MAP,
        "SOCRADAR_API_KEY": "legacy", "SOCRADAR_COMPANY_ID": "legacy-1",
        "ENTRA_CLIENT_ID": "app-1", "ENTRA_TENANT_IDS": "tenant-GLOBAL",
        "DCR_IMMUTABLE_ID": "dcr", "DCR_ENDPOINT": "https://x",
        "STORAGE_ACCOUNT_NAME": "sa",
        "ENABLE_USER_LOOKUP": "true", "ENABLE_REVOKE_SESSION": "true",
        "ENABLE_DISABLE_ACCOUNT": "true", "ENTRA_ACTION_MODE": "apply",
    }
    env.update(over)
    return env


def _run_probe(email, company_id, env=None, apply=None, ledger=None, law_calls=None):
    """Probe with a fake directory; records which tenants were asked."""
    asked = []

    def fake_lookup(addr, headers):
        tenant = headers["X-Test-Tenant"]
        asked.append((tenant, addr))
        user = DIRECTORY.get(tenant, {}).get(addr)
        return (user, 200) if user else (None, 404)

    body = {"email": email, "company_id": company_id}
    if apply is not None:
        body["apply"] = apply

    from actions.action_ledger import InMemoryActionLedger
    if ledger is None:
        ledger = InMemoryActionLedger()

    def record_law(*a, **k):
        if law_calls is not None:
            law_calls.append((a, k))

    with mock.patch.dict(function_app.os.environ, env or _env(), clear=True), \
         mock.patch.object(function_app.entra, "revoke_sessions", return_value=True) as revoke, \
         mock.patch.object(function_app.entra, "lookup_user", side_effect=fake_lookup), \
         mock.patch.object(function_app.ledger_mod, "ActionLedger", return_value=ledger), \
         mock.patch.object(function_app, "DefaultAzureCredential", lambda *a, **k: None), \
         mock.patch.object(function_app.law, "write_lifecycle_event", side_effect=record_law), \
         mock.patch.object(function_app, "_acquire_tenant_tokens",
                           side_effect=lambda c, cid: {t: {"X-Test-Tenant": t}
                                                       for t in c["tenant_ids"]}):
        resp = function_app.leak_probe(_Req(body))
        calls = revoke.call_count
    payload = json.loads(resp.get_body() if hasattr(resp, "get_body") else resp.body)
    payload["_revoke_calls"] = calls
    return payload, asked


class _Resp:
    """The stubbed HttpResponse keeps its payload on .body."""


def _payload(resp):
    return json.loads(resp)


class ProbeIsolationTest(unittest.TestCase):
    def test_company_finds_person_in_its_own_tenant(self):
        payload, asked = _run_probe("probe@x.com", "330")
        self.assertTrue(payload["found"])
        self.assertEqual(payload["found_in_tenant"], "tenant-A")
        self.assertEqual(payload["tenants_searched"], ["tenant-A"])
        self.assertEqual([t for t, _ in asked], ["tenant-A"])

    def test_other_company_does_not_reach_that_tenant(self):
        """The person exists — in tenant-A. Company 440 owns tenant-B, so it
        must neither find them nor send a single request to tenant-A."""
        payload, asked = _run_probe("probe@x.com", "440")
        self.assertFalse(payload["found"])
        self.assertEqual(payload["tenants_searched"], ["tenant-B"])
        self.assertNotIn("tenant-A", [t for t, _ in asked])
        self.assertEqual(payload["would_run"], [])

    def test_global_tenant_setting_is_never_used(self):
        _, asked = _run_probe("probe@x.com", "330")
        self.assertNotIn("tenant-GLOBAL", [t for t, _ in asked])

    def test_unknown_company_is_rejected(self):
        with mock.patch.dict(function_app.os.environ, _env(), clear=True):
            resp = function_app.leak_probe(_Req({"email": "probe@x.com", "company_id": "999"}))
        self.assertEqual(resp.status_code, 404)


class ProbeCarriesTheSameBrakesAsTheTimer(unittest.TestCase):
    """This endpoint mutates the directory, so it needs the guards the timer
    has. Without them a function key is a loop away from unbounded changes,
    and none of it reaches the audit trail."""

    def test_repeating_the_call_does_not_repeat_the_action(self):
        from actions.action_ledger import InMemoryActionLedger
        ledger = InMemoryActionLedger()

        first, _ = _run_probe("probe@x.com", "330", apply=True, ledger=ledger)
        second, _ = _run_probe("probe@x.com", "330", apply=True, ledger=ledger)

        self.assertEqual(first["applied"], ["revoke_session"])
        self.assertEqual(first["_revoke_calls"], 1)
        self.assertEqual(second["applied"], ["revoke_session_skipped_idempotent"])
        self.assertEqual(second["_revoke_calls"], 0, "the second call must touch nobody")

    def test_an_address_outside_the_allowlist_is_not_acted_on(self):
        env = _env(ENTRA_ID_VERIFIED_DOMAINS="contoso.com")
        payload, _ = _run_probe("probe@x.com", "330", env=env, apply=True)

        self.assertEqual(payload["apply_reason"],
                         "address is outside the verified-domain allowlist")
        self.assertEqual(payload["applied"], [])
        self.assertEqual(payload["_revoke_calls"], 0)
        self.assertTrue(payload["found"], "it is still reported, just not acted on")

    def test_an_allowlisted_address_still_goes_through(self):
        env = _env(ENTRA_ID_VERIFIED_DOMAINS="x.com")
        payload, _ = _run_probe("probe@x.com", "330", env=env, apply=True)
        self.assertEqual(payload["applied"], ["revoke_session"])

    def test_the_change_reaches_the_audit_trail(self):
        calls = []
        _run_probe("probe@x.com", "330", apply=True, law_calls=calls)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][1].get("event_type"), "leak_probe_applied")

    def test_a_read_only_probe_writes_no_audit_event(self):
        calls = []
        _run_probe("probe@x.com", "330", apply=False, law_calls=calls)
        self.assertEqual(calls, [])


class ProbeApplyGatesTest(unittest.TestCase):
    """Responding needs all three consents. Any one missing keeps it read-only."""

    def test_all_three_gates_open_applies(self):
        payload, _ = _run_probe("probe@x.com", "330", apply=True)
        self.assertEqual(payload["apply_reason"], "applied")
        self.assertEqual(payload["applied"], ["revoke_session"])
        self.assertTrue(payload["mutated"])
        self.assertEqual(payload["_revoke_calls"], 1)

    def test_plan_mode_blocks_apply(self):
        payload, _ = _run_probe("probe@x.com", "330",
                                env=_env(ENTRA_ACTION_MODE="plan"), apply=True)
        self.assertEqual(payload["apply_reason"], "deployment is in plan mode")
        self.assertFalse(payload["mutated"])
        self.assertEqual(payload["_revoke_calls"], 0)

    def test_request_must_ask_for_it(self):
        payload, _ = _run_probe("probe@x.com", "330")  # no apply field
        self.assertEqual(payload["apply_reason"], "request did not ask to apply")
        self.assertFalse(payload["mutated"])
        self.assertEqual(payload["_revoke_calls"], 0)

    def test_other_tenants_person_is_never_touched(self):
        """Company 440 owns tenant-B; the person lives in tenant-A. Even with
        apply mode on and apply requested, nothing may happen to them."""
        payload, asked = _run_probe("probe@x.com", "440", apply=True)
        self.assertEqual(payload["apply_reason"],
                         "not found in this company's own tenants")
        self.assertFalse(payload["mutated"])
        self.assertEqual(payload["_revoke_calls"], 0)
        self.assertNotIn("tenant-A", [t for t, _ in asked])

    def test_irreversible_actions_stay_with_the_timer(self):
        payload, _ = _run_probe(
            "probe@x.com", "330",
            env=_env(ENABLE_DISABLE_ACCOUNT="true",
                     ENABLE_FORCE_MFA_REREGISTRATION="true"),
            apply=True)
        self.assertNotIn("disable_account", payload["would_run"])
        self.assertNotIn("force_mfa_reregistration", payload["would_run"])
        self.assertNotIn("disable_account", payload["applied"])


class ProbeSaysWhetherItLookedAtAll(unittest.TestCase):
    """An unread answer must not be reported as a negative one.

    When no tenant is reachable the probe searched nobody, so it establishes
    nothing about the address. Saying "not found in this company's own tenants"
    there answers a question the run never asked, and the operator's next step
    is different in each case: a real miss means the address is not in the
    directory, an unread one means the lookup is off or no token was obtained.
    """

    def _probe_with_no_tenant_reached(self, env):
        with mock.patch.dict(function_app.os.environ, env, clear=True), \
             mock.patch.object(function_app.entra, "lookup_user",
                               side_effect=AssertionError("must not look anyone up")), \
             mock.patch.object(function_app, "DefaultAzureCredential", lambda *a, **k: None), \
             mock.patch.object(function_app.law, "write_lifecycle_event"), \
             mock.patch.object(function_app, "_acquire_tenant_tokens",
                               side_effect=lambda c, cid: {}):
            resp = function_app.leak_probe(
                _Req({"email": "probe@x.com", "company_id": "330"}))
        return json.loads(resp.get_body() if hasattr(resp, "get_body") else resp.body)

    def test_nothing_searched_is_not_reported_as_not_found(self):
        d = self._probe_with_no_tenant_reached(_env())
        self.assertEqual(d["tenants_searched"], [])
        self.assertNotIn("not found", d["apply_reason"],
                         "an unread lookup was reported as a miss")

    def test_it_says_no_tenant_was_searched(self):
        d = self._probe_with_no_tenant_reached(_env())
        self.assertIn("no tenant was searched", d["apply_reason"])

    def test_a_disabled_lookup_is_named_as_the_cause(self):
        # The two causes need different fixes, so the message has to separate
        # them: switch the lookup on, versus find out why no token was issued.
        d = self._probe_with_no_tenant_reached(_env(ENABLE_USER_LOOKUP="false"))
        self.assertIn("lookup is disabled", d["apply_reason"])

    def test_a_missing_token_is_named_as_the_cause(self):
        d = self._probe_with_no_tenant_reached(_env())
        self.assertIn("no Graph token", d["apply_reason"])

    def test_a_real_miss_still_says_not_found(self):
        # Guards the change: the honest negative must survive, or the fix would
        # have traded one wrong message for another.
        d, asked = _run_probe("nobody@x.com", "330")
        self.assertTrue(asked, "the fixture never searched, so this proves nothing")
        self.assertEqual(d["apply_reason"], "not found in this company's own tenants")


if __name__ == "__main__":
    unittest.main()
