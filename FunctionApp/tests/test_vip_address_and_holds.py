"""VIP records name a person, not an address — and a first run that holds.

Both guarantees here were broken while every test passed, and both were found by
reading rather than by the suite.

1. `vip._map_record` read `vipName` as the address. Measured against a live
   feed: every record had a space in vipName, none had an '@', none carried an
   `email` key, and none had an '@' in `keyword` either — where an address
   appeared at all it was inside free text. So every VIP record was looked up in
   Microsoft Graph as "Firstname Lastname", Graph answered 404 exactly as it
   does for an address nobody has heard of, and the run recorded clean misses
   with error_count 0. VIP monitoring could not have matched anyone.

2. A held checkpoint on a source that had never checkpointed saved nothing,
   because the branch required a truthy `chk`. consecutive_holds never
   persisted, so MAX_CONSECUTIVE_HOLDS could never trip and the same window was
   re-read and re-written on every run.
"""

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from test_import_path import _ensure_azure_stub                 # noqa: E402

_ensure_azure_stub()

from actions import law_writer                                  # noqa: E402
from sources.vip import VipFetcher                              # noqa: E402
import function_app                                             # noqa: E402


# Shaped like the live feed: a display name, no email key, keyword is the
# monitored term rather than an address.
LIVE_VIP_RECORD = {
    "alarmId": 91, "discoveryDate": "2026-06-02",
    "history": [{"date": "2026-06-02", "detail": "seen", "operator": "sys"}],
    "keyword": "Emma Bank", "notificationId": 7,
    "relatedAlarm": {"status": "OPEN", "type": "vip", "url": "https://x.invalid"},
    "source": "forum", "status": "OPEN", "statusReason": "none",
    "vipName": "Emma Taylor",
}


class VipAddressSelection(unittest.TestCase):
    def _mapped(self, **overrides):
        rec = dict(LIVE_VIP_RECORD, **overrides)
        return VipFetcher()._map_record(rec, {})

    def test_a_display_name_is_not_treated_as_an_address(self):
        # The defect verbatim: vipName held "Emma Taylor" and became the email.
        self.assertEqual(self._mapped()["email"], "")

    def test_the_display_name_is_still_reported_in_its_own_field(self):
        # Dropping it from `email` must not lose it from the row.
        self.assertEqual(self._mapped()["vip_name"], "Emma Taylor")

    def test_an_address_in_vip_name_is_used(self):
        row = self._mapped(vipName="emma.taylor@bank.invalid")
        self.assertEqual(row["email"], "emma.taylor@bank.invalid")

    def test_an_address_in_the_email_field_is_used_when_vip_name_is_a_name(self):
        row = self._mapped(email="emma@bank.invalid")
        self.assertEqual(row["email"], "emma@bank.invalid")

    def test_an_address_in_keyword_is_used_as_a_last_resort(self):
        row = self._mapped(keyword="emma@bank.invalid")
        self.assertEqual(row["email"], "emma@bank.invalid")

    def test_the_first_candidate_holding_an_address_wins(self):
        row = self._mapped(vipName="a@x.invalid", email="b@x.invalid",
                           keyword="c@x.invalid")
        self.assertEqual(row["email"], "a@x.invalid")

    def test_a_single_word_is_not_an_address_either(self):
        # Every other negative fixture here has a space in it, so on its own the
        # suite only proves "a two-word string is not an address". The rule is
        # the '@', not the space.
        row = self._mapped(vipName="emmataylor", keyword="handle123")
        self.assertEqual(row["email"], "")

    def test_a_name_in_an_earlier_field_does_not_block_a_later_address(self):
        # The ordering has to skip non-addresses, not stop at the first
        # non-empty value — that was the original bug in a different dress.
        row = self._mapped(vipName="Emma Taylor", keyword="emma@x.invalid")
        self.assertEqual(row["email"], "emma@x.invalid")


class RecordWithoutAnAddressIsStillAudited(unittest.TestCase):
    """A record with nothing to look up must reach Log Analytics anyway."""

    def _rows(self, employees):
        conf = {
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
        with mock.patch.object(function_app.src_vip, "fetch", return_value=employees), \
             mock.patch.object(function_app.cp, "load", return_value={}), \
             mock.patch.object(function_app.cp, "save"), \
             mock.patch.object(function_app.entra, "lookup_user",
                               return_value=({"id": "u1", "accountEnabled": True}, 200)) as lu, \
             mock.patch.object(law_writer, "_upload", return_value=True) as up:
            function_app._process_source(
                "vip", conf, None, {"t-a": {"Authorization": "x"}},
                deadline=float("inf"), checkpoint_key="vip:330")
        stream = law_writer.STREAM_MAP["vip"]
        calls = [c for c in up.call_args_list if c[0][1] == stream]
        rows = calls[0][0][2] if calls else []
        return rows, lu

    def _employee(self, email):
        return {
            "email": email, "company_id": "330", "source": "vip",
            "is_employee": True, "alarm_id": 1, "vip_name": "Emma Taylor",
            "password_present": False, "password_masked": None,
            "is_plaintext": False,
            "_checkpoint_update": {"last_start_date": "2026-07-27"},
        }

    def test_a_record_with_no_address_still_lands_in_law(self):
        rows, _ = self._rows([self._employee("")])
        self.assertEqual(len(rows), 1,
                         "the finding vanished from the customer's audit trail")

    def test_it_says_why_it_was_not_looked_up(self):
        rows, _ = self._rows([self._employee("")])
        self.assertEqual(rows[0].get("entra_status"), "skipped_no_address")

    def test_graph_is_not_asked_about_a_record_with_no_address(self):
        _, lookup = self._rows([self._employee("")])
        lookup.assert_not_called()

    def _appended_record(self, employee):
        """Capture the record as it leaves _process_source, before cleaning.

        law_writer strips the whole `sanitized` sub-dict on its way out, so
        looking at the uploaded row cannot tell whether the plaintext was still
        attached when the record was handed over. This looks at the handover.
        """
        conf = {
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
        seen = {}

        def capture(conf_, source, records):
            seen["records"] = records
            return True

        with mock.patch.object(function_app.src_botnet, "fetch",
                               return_value=[employee]), \
             mock.patch.object(function_app.cp, "load", return_value={}), \
             mock.patch.object(function_app.cp, "save"), \
             mock.patch.object(function_app.law, "write_records", capture), \
             mock.patch.object(function_app.law, "write_audit"):
            function_app._process_source(
                "botnet", conf, None, {"t-a": {"Authorization": "x"}},
                deadline=float("inf"), checkpoint_key="botnet:330")
        return (seen.get("records") or [None])[0]

    def test_a_record_with_no_address_does_not_carry_the_plaintext_onward(self):
        # A feed record can lack an address and still carry a credential. The
        # early exit for "nothing to look up" sits above everything that would
        # otherwise scrub it, so the scrub has to come first — otherwise the
        # plaintext travels on inside the record for every later handler and
        # log line to pick up.
        rec = self._appended_record({
            "email": "", "company_id": "330", "source": "botnet",
            "is_employee": True, "alarm_id": 1,
            "password_present": True, "password_masked": "a***3",
            "is_plaintext": True,
            "sanitized": {"is_plaintext": True, "_raw": "Zm4rQ7-plaintext-Ww91"},
            "_checkpoint_update": {"last_start_date": "2026-07-27"},
        })
        self.assertIsNotNone(rec, "the record never reached the writer")
        self.assertEqual(rec.get("entra_status"), "skipped_no_address")
        self.assertNotIn("_raw", rec.get("sanitized", {}),
                         "the plaintext credential travelled on with the record")
        self.assertNotIn("Zm4rQ7-plaintext-Ww91", repr(rec))

    def test_a_record_with_an_address_is_looked_up_as_before(self):
        # Guards the fixture: if nothing is ever looked up, the assertions
        # above would hold for the wrong reason.
        rows, lookup = self._rows([self._employee("emma@x.invalid")])
        self.assertEqual(rows[0].get("entra_status"), "found")
        self.assertTrue(lookup.called)


class AFirstRunThatHoldsRemembersIt(unittest.TestCase):
    """consecutive_holds has to persist even with no prior checkpoint."""

    def _save_calls(self, prior_checkpoint):
        conf = {
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
        employees = [{
            "email": "a@x.invalid", "company_id": "330", "source": "botnet",
            "is_employee": True, "alarm_id": 1,
            "password_present": True, "password_masked": "a***3",
            "is_plaintext": False,
            "_checkpoint_update": {"last_start_date": "2026-07-27"},
        }]
        # A 403 is a lookup failure, which is what makes the run hold.
        with mock.patch.object(function_app.src_botnet, "fetch", return_value=employees), \
             mock.patch.object(function_app.cp, "load", return_value=prior_checkpoint), \
             mock.patch.object(function_app.cp, "save") as save, \
             mock.patch.object(function_app.entra, "lookup_user",
                               return_value=(None, 403)), \
             mock.patch.object(law_writer, "_upload", return_value=True):
            function_app._process_source(
                "botnet", conf, None, {"t-a": {"Authorization": "x"}},
                deadline=float("inf"), checkpoint_key="botnet:330")
        return save.call_args_list

    def test_a_held_first_run_persists_the_holds_counter(self):
        calls = self._save_calls({})
        self.assertTrue(calls, "a held first run saved nothing, so the "
                               "abandon escape can never arm")
        self.assertEqual(calls[-1][0][3].get("consecutive_holds"), 1)

    def test_it_does_not_invent_a_window_position(self):
        # Saving the counter must not also claim a last_start_date, or the next
        # run would resume from a window this one never finished.
        calls = self._save_calls({})
        self.assertNotIn("last_start_date", calls[-1][0][3])

    def test_a_held_later_run_still_keeps_its_position(self):
        calls = self._save_calls({"last_start_date": "2026-06-01",
                                  "consecutive_holds": 2})
        saved = calls[-1][0][3]
        self.assertEqual(saved.get("last_start_date"), "2026-06-01")
        self.assertEqual(saved.get("consecutive_holds"), 3)


if __name__ == "__main__":
    unittest.main()
