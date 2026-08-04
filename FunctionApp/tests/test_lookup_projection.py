"""What the lookup asks Graph for, and what the audit row is allowed to claim.

Microsoft Graph answers GET /users/{id} with a fixed default set of eleven
properties. accountEnabled is not among them. Verified live against the real
service on 2026-07-30:

    default projection -> businessPhones, displayName, givenName, id, jobTitle,
                          mail, mobilePhone, officeLocation, preferredLanguage,
                          surname, userPrincipalName        (no accountEnabled)
    ?$select=accountEnabled -> True

Every other test in this suite mocks the lookup as
`({"id": "u1", "accountEnabled": True}, 200)` — twelve places do. That mock
supplies exactly the property the real call omits, so the whole suite was
structurally unable to see that `entra_account_enabled` in the audit trail came
from a default and not from Entra ID. These tests mock what Graph really
returns instead.
"""

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from test_import_path import _ensure_azure_stub                 # noqa: E402

_ensure_azure_stub()

from actions import entra_id                                    # noqa: E402
from actions import law_writer                                  # noqa: E402
import function_app                                             # noqa: E402


# The real default projection: no accountEnabled, because Graph does not send it.
GRAPH_DEFAULT_USER = {
    "businessPhones": [], "displayName": "A Person", "givenName": "A",
    "id": "u-1", "jobTitle": None, "mail": "a@x.com", "mobilePhone": None,
    "officeLocation": None, "preferredLanguage": None, "surname": "Person",
    "userPrincipalName": "a@x.com",
}


def _conf_for_botnet():
    return {
        "socradar_company_id": "330", "socradar_api_key": "k",
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


class LookupAsksForWhatItReports(unittest.TestCase):
    """The lookup must select every property the audit trail later reports."""

    def _captured_url(self, email="a@x.com"):
        captured = {}

        class Resp:
            status_code = 200

            @staticmethod
            def json():
                return dict(GRAPH_DEFAULT_USER)

        def fake_request(method, url, headers, **kw):
            captured["url"] = url
            return Resp()

        with mock.patch.object(entra_id, "_graph_request", fake_request):
            entra_id.lookup_user(email, {"Authorization": "x"})
        return captured["url"]

    def test_lookup_selects_account_enabled(self):
        # Naming the property is the only way it arrives. Without this the audit
        # column is sourced from a field the response never contained.
        self.assertIn("accountEnabled", self._captured_url())

    def test_lookup_selects_the_object_id(self):
        # entra_user_id is what lets a customer line a row up against Entra ID's
        # own audit log, so it has to be selected too.
        url = self._captured_url()
        select = url.split("$select=", 1)[1]
        self.assertIn("id", select.split(","))

    def test_select_is_a_query_not_a_second_path_segment(self):
        url = self._captured_url()
        self.assertIn("?$select=", url)
        self.assertEqual(url.count("?"), 1)

    def test_a_hostile_address_cannot_forge_the_select(self):
        # The address arrives from a third-party feed. If '?' or '#' survived
        # unescaped it could replace or truncate the projection and quietly
        # change which properties come back.
        url = self._captured_url("victim@x.com?$select=id#")
        self.assertEqual(url.count("?$select="), 1)
        self.assertTrue(url.endswith(entra_id.LOOKUP_SELECT))


class AuditRowClaimsOnlyWhatWasRead(unittest.TestCase):
    """An absent property must not become a value in the audit trail."""

    def _row_for(self, lookup_result):
        conf = {
            "socradar_company_id": "330", "socradar_api_key": "k",
            "socradar_base_url": "https://example.invalid",
            # These exact key names matter: without them the writer logs an
            # error and returns False, and every assertion below would pass by
            # never reaching the uploader at all.
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
        employees = [{
            "email": "a@x.com", "company_id": "330", "source": "botnet",
            "is_employee": True, "alarm_id": 1,
            "password_present": True, "password_masked": "a***3",
            "is_plaintext": False,
            "_checkpoint_update": {"last_start_date": "2026-07-27"},
        }]
        with mock.patch.object(function_app.src_botnet, "fetch", return_value=employees), \
             mock.patch.object(function_app.cp, "load", return_value={}), \
             mock.patch.object(function_app.cp, "save"), \
             mock.patch.object(function_app.entra, "lookup_user",
                               return_value=lookup_result), \
             mock.patch.object(law_writer, "_upload", return_value=True) as up:
            function_app._process_source(
                "botnet", conf, None, {"t-a": {"Authorization": "x"}},
                deadline=float("inf"), checkpoint_key="botnet:330")
        stream = law_writer.STREAM_MAP["botnet"]
        calls = [c for c in up.call_args_list if c[0][1] == stream]
        self.assertTrue(calls, "no botnet record reached the uploader")
        return calls[0][0][2][0]

    def test_found_user_is_recorded(self):
        # Guards the fixture itself: if the row never says "found", the
        # assertions below would pass for the wrong reason.
        row = self._row_for((dict(GRAPH_DEFAULT_USER), 200))
        self.assertEqual(row.get("entra_status"), "found")
        self.assertEqual(row.get("entra_user_id"), "u-1")

    def test_absent_account_enabled_is_not_reported_at_all(self):
        # The whole point. Graph's default projection omits the property; the
        # row must not answer a question it never asked.
        #
        # Asserting "not True" (or "not True and not False") is too narrow: a
        # default of "unknown", None or 0 would satisfy it while still putting a
        # value the code invented into a column a customer reads as fact. The
        # column has to be absent.
        row = self._row_for((dict(GRAPH_DEFAULT_USER), 200))
        self.assertNotIn(
            "entra_account_enabled", row,
            "the row reports a state that was never read",
        )

    def test_a_disabled_account_is_recorded_as_disabled(self):
        user = dict(GRAPH_DEFAULT_USER, accountEnabled=False)
        row = self._row_for((user, 200))
        self.assertIs(row.get("entra_account_enabled"), False)

    def test_an_enabled_account_is_recorded_as_enabled(self):
        user = dict(GRAPH_DEFAULT_USER, accountEnabled=True)
        row = self._row_for((user, 200))
        self.assertIs(row.get("entra_account_enabled"), True)

    def test_disabled_and_absent_do_not_look_alike(self):
        # False and "unread" have to stay distinguishable, or a genuinely
        # disabled account is indistinguishable from one nobody checked.
        absent = self._row_for((dict(GRAPH_DEFAULT_USER), 200))
        disabled = self._row_for((dict(GRAPH_DEFAULT_USER, accountEnabled=False), 200))
        self.assertNotEqual(
            absent.get("entra_account_enabled", "__absent__"),
            disabled.get("entra_account_enabled"),
        )


class TheTwoHalvesTogether(unittest.TestCase):
    """Selecting the property and reporting it have to work as one thing.

    Tested apart, each half passes while the pair is broken: a lookup that asks
    for accountEnabled and a writer that reports it are both satisfied by a
    transport that returns the default projection anyway. This drives the real
    `lookup_user` through a fake Graph that honours $select the way the service
    does — the property comes back only if it was asked for.
    """

    def _row_through_a_graph_that_honours_select(self, enabled):
        captured = {}

        class Resp:
            status_code = 200

            @staticmethod
            def json():
                body = {k: v for k, v in GRAPH_DEFAULT_USER.items()}
                select = captured.get("url", "").partition("$select=")[2]
                if "accountEnabled" in select.split(","):
                    body["accountEnabled"] = enabled
                return body

        def fake_request(method, url, headers, **kw):
            captured["url"] = url
            return Resp()

        conf = _conf_for_botnet()
        employees = [{
            "email": "a@x.com", "company_id": "330", "source": "botnet",
            "is_employee": True, "alarm_id": 1,
            "password_present": True, "password_masked": "a***3",
            "is_plaintext": False,
            "_checkpoint_update": {"last_start_date": "2026-07-27"},
        }]
        with mock.patch.object(function_app.src_botnet, "fetch", return_value=employees), \
             mock.patch.object(function_app.cp, "load", return_value={}), \
             mock.patch.object(function_app.cp, "save"), \
             mock.patch.object(entra_id, "_graph_request", fake_request), \
             mock.patch.object(law_writer, "_upload", return_value=True) as up:
            function_app._process_source(
                "botnet", conf, None, {"t-a": {"Authorization": "x"}},
                deadline=float("inf"), checkpoint_key="botnet:330")
        stream = law_writer.STREAM_MAP["botnet"]
        calls = [c for c in up.call_args_list if c[0][1] == stream]
        assert calls, "no botnet record reached the uploader"
        return calls[0][0][2][0]

    def test_an_enabled_account_survives_the_round_trip(self):
        row = self._row_through_a_graph_that_honours_select(True)
        self.assertEqual(row.get("entra_status"), "found")
        self.assertIs(row.get("entra_account_enabled"), True)

    def test_a_disabled_account_survives_the_round_trip(self):
        # The value that matters most: an account already switched off must not
        # be reported as live just because the property was hard to obtain.
        row = self._row_through_a_graph_that_honours_select(False)
        self.assertIs(row.get("entra_account_enabled"), False)


if __name__ == "__main__":
    unittest.main()
