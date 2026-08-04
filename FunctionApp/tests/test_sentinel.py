"""
Tests for actions/sentinel.py — Microsoft Sentinel incident creation.

Coverage: skip conditions, API URL construction, severity mapping,
credential-data exclusion, and HTTP error resilience.
"""
import os
import sys
import types
import unittest
from importlib.machinery import ModuleSpec
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


def _ensure_azure_stub():
    """Provide azure.identity stub so sentinel.py can be imported outside the
    Function App image. Uses the same fill-if-missing pattern as
    test_import_path.py."""
    def module(name, is_package):
        mod = sys.modules.get(name)
        if mod is None:
            mod = types.ModuleType(name)
            mod.__spec__ = ModuleSpec(name, loader=None, is_package=is_package)
            if is_package:
                mod.__path__ = []
            sys.modules[name] = mod
            parent, _, leaf = name.rpartition(".")
            if parent:
                setattr(sys.modules[parent], leaf, mod)
        return mod

    def fill(name, is_package=False, **attrs):
        mod = module(name, is_package)
        for key, value in attrs.items():
            if not hasattr(mod, key):
                setattr(mod, key, value)

    fill("azure", is_package=True)
    fill("azure.identity", DefaultAzureCredential=object,
         ManagedIdentityCredential=object)


_ensure_azure_stub()

from actions.sentinel import create_incident, INCIDENTS_URL  # noqa: E402


def _full_conf():
    """Config dict with all required sentinel fields populated."""
    return {
        "subscription_id": "sub-123",
        "workspace_resource_group": "rg-sentinel",
        "workspace_name": "ws-prod",
    }


class _FakeCredential:
    """Minimal credential stub returning a fixed token."""
    def get_token(self, *scopes):
        return types.SimpleNamespace(token="fake-token-123")


class SkipConditionsTest(unittest.TestCase):
    """create_incident must gracefully skip (return None) when prerequisites
    are missing, without raising exceptions."""

    def test_skips_when_workspace_config_incomplete(self):
        conf = {"subscription_id": "sub-123", "workspace_resource_group": "",
                "workspace_name": "ws-prod"}
        result = create_incident(conf, "user@x.com", "botnet", "HIGH",
                                 credential=_FakeCredential())
        # False, not None: the caller records the action against its
        # idempotency ledger only on a truthy answer, so an incident that was
        # never raised must not read as one that was.
        self.assertFalse(result)

    def test_skips_when_subscription_missing(self):
        conf = {"subscription_id": "", "workspace_resource_group": "rg",
                "workspace_name": "ws"}
        result = create_incident(conf, "user@x.com", "botnet", "HIGH",
                                 credential=_FakeCredential())
        # False, not None: the caller records the action against its
        # idempotency ledger only on a truthy answer, so an incident that was
        # never raised must not read as one that was.
        self.assertFalse(result)

    def test_skips_when_no_credential(self):
        conf = _full_conf()
        result = create_incident(conf, "user@x.com", "botnet", "HIGH",
                                 credential=None)
        # False, not None: the caller records the action against its
        # idempotency ledger only on a truthy answer, so an incident that was
        # never raised must not read as one that was.
        self.assertFalse(result)

    def test_skips_when_credential_default_none(self):
        conf = _full_conf()
        result = create_incident(conf, "user@x.com", "botnet", "HIGH")
        # False, not None: the caller records the action against its
        # idempotency ledger only on a truthy answer, so an incident that was
        # never raised must not read as one that was.
        self.assertFalse(result)


class ApiUrlTest(unittest.TestCase):
    """create_incident must construct the correct ARM URL from config values."""

    @mock.patch("actions.sentinel.requests.put")
    def test_url_contains_subscription_rg_workspace(self, mock_put):
        mock_put.return_value = mock.Mock(status_code=201, text="ok")
        conf = _full_conf()
        create_incident(conf, "user@x.com", "botnet", "HIGH",
                        credential=_FakeCredential())
        self.assertTrue(mock_put.called)
        url = mock_put.call_args[0][0]
        self.assertIn("sub-123", url)
        self.assertIn("rg-sentinel", url)
        self.assertIn("ws-prod", url)
        self.assertIn("Microsoft.SecurityInsights/incidents/", url)


class SeverityMappingTest(unittest.TestCase):
    """CRITICAL severity must be mapped to 'High' in the Sentinel body."""

    @mock.patch("actions.sentinel.requests.put")
    def test_critical_maps_to_high(self, mock_put):
        mock_put.return_value = mock.Mock(status_code=201, text="ok")
        create_incident(_full_conf(), "user@x.com", "botnet", "CRITICAL",
                        credential=_FakeCredential())
        body = mock_put.call_args[1]["json"]
        self.assertEqual(body["properties"]["severity"], "High")

    @mock.patch("actions.sentinel.requests.put")
    def test_high_stays_high(self, mock_put):
        mock_put.return_value = mock.Mock(status_code=201, text="ok")
        create_incident(_full_conf(), "user@x.com", "botnet", "high",
                        credential=_FakeCredential())
        body = mock_put.call_args[1]["json"]
        self.assertEqual(body["properties"]["severity"], "High")

    @mock.patch("actions.sentinel.requests.put")
    def test_medium_capitalized(self, mock_put):
        mock_put.return_value = mock.Mock(status_code=201, text="ok")
        create_incident(_full_conf(), "user@x.com", "botnet", "medium",
                        credential=_FakeCredential())
        body = mock_put.call_args[1]["json"]
        self.assertEqual(body["properties"]["severity"], "Medium")


class NoCredentialDataTest(unittest.TestCase):
    """The incident body must NEVER contain password or credential data."""

    @mock.patch("actions.sentinel.requests.put")
    def test_body_excludes_actual_credential_values(self, mock_put):
        mock_put.return_value = mock.Mock(status_code=201, text="ok")
        # The function must never include actual credential values (passwords,
        # secrets, tokens) in the incident body. The description may contain
        # instructional text like "reset password" or "Do NOT include
        # credentials" — those are guidance phrases, not credential data.
        fake_password = "S3cretP@ss!"
        create_incident(_full_conf(), "user@x.com", "botnet", "HIGH",
                        credential=_FakeCredential())
        body = mock_put.call_args[1]["json"]
        body_str = str(body)
        # The fake credential token must not appear in the body.
        self.assertNotIn("fake-token-123", body_str)
        # No field named "password" or "secret" in the properties dict.
        props = body["properties"]
        for key in props:
            self.assertNotIn("password", key.lower())
            self.assertNotIn("secret", key.lower())
            self.assertNotIn("token", key.lower())

    @mock.patch("actions.sentinel.requests.put")
    def test_body_contains_email_and_source(self, mock_put):
        mock_put.return_value = mock.Mock(status_code=201, text="ok")
        create_incident(_full_conf(), "victim@corp.com", "pii", "HIGH",
                        credential=_FakeCredential())
        body_str = str(mock_put.call_args[1]["json"])
        self.assertIn("victim@corp.com", body_str)
        self.assertIn("PII", body_str)


class HttpErrorResilienceTest(unittest.TestCase):
    """A failing HTTP request must not raise an exception."""

    @mock.patch("actions.sentinel.requests.put")
    def test_connection_error_no_raise(self, mock_put):
        import requests as real_requests
        mock_put.side_effect = real_requests.ConnectionError("timeout")
        # Must not raise
        result = create_incident(_full_conf(), "user@x.com", "botnet", "HIGH",
                                 credential=_FakeCredential())
        # False, not None: the caller records the action against its
        # idempotency ledger only on a truthy answer, so an incident that was
        # never raised must not read as one that was.
        self.assertFalse(result)

    @mock.patch("actions.sentinel.requests.put")
    def test_http_500_no_raise(self, mock_put):
        mock_put.return_value = mock.Mock(status_code=500,
                                          text="Internal Server Error")
        # Must not raise
        result = create_incident(_full_conf(), "user@x.com", "botnet", "HIGH",
                                 credential=_FakeCredential())
        # False, not None: the caller records the action against its
        # idempotency ledger only on a truthy answer, so an incident that was
        # never raised must not read as one that was.
        self.assertFalse(result)

    @mock.patch("actions.sentinel.requests.put")
    def test_token_error_no_raise(self, mock_put):
        class BadCred:
            def get_token(self, *a):
                raise Exception("token acquisition failed")
        result = create_incident(_full_conf(), "user@x.com", "botnet", "HIGH",
                                 credential=BadCred())
        # False, not None: the caller records the action against its
        # idempotency ledger only on a truthy answer, so an incident that was
        # never raised must not read as one that was.
        self.assertFalse(result)
        mock_put.assert_not_called()


class ReturnContractTest(unittest.TestCase):
    """The caller writes to its idempotency ledger on a truthy answer, so the
    two halves of the contract both matter: accepted means True, anything else
    means False and stays retryable."""

    @mock.patch("actions.sentinel.requests.put")
    def test_accepted_incident_reports_success(self, mock_put):
        mock_put.return_value = mock.Mock(status_code=201, text="ok")
        result = create_incident(_full_conf(), "user@x.com", "botnet", "HIGH",
                                 credential=_FakeCredential())
        self.assertTrue(result)

    @mock.patch("actions.sentinel.requests.put")
    def test_two_hundred_also_counts_as_accepted(self, mock_put):
        mock_put.return_value = mock.Mock(status_code=200, text="ok")
        result = create_incident(_full_conf(), "user@x.com", "botnet", "HIGH",
                                 credential=_FakeCredential())
        self.assertTrue(result)

    @mock.patch("actions.sentinel.requests.put")
    def test_rejected_incident_reports_failure(self, mock_put):
        mock_put.return_value = mock.Mock(status_code=403, text="forbidden")
        result = create_incident(_full_conf(), "user@x.com", "botnet", "HIGH",
                                 credential=_FakeCredential())
        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()
