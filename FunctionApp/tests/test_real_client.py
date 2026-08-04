"""RealFormerListClient unit test — conformance with the DRP Former Employees contract.
requests is mocked; the real API is never called.

Run: python3 tests/test_real_client.py  (from the FunctionApp root)
"""
import os
import sys
import types
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Stub the azure.data.tables import (the mock client is not used in this test)
azure_pkg = types.ModuleType("azure")
tables_mod = types.ModuleType("azure.data.tables")
tables_mod.TableServiceClient = object
tables_mod.TableEntity = dict
core_mod = types.ModuleType("azure.core.exceptions")
core_mod.ResourceNotFoundError = type("ResourceNotFoundError", (Exception,), {})
core_mod.ResourceExistsError = type("ResourceExistsError", (Exception,), {})
sys.modules.setdefault("azure", azure_pkg)
sys.modules["azure.data.tables"] = tables_mod
sys.modules["azure.core.exceptions"] = core_mod

from actions.socradar_former import RealFormerListClient


def _resp(status=200, json_body=None, text=""):
    r = mock.Mock()
    r.status_code = status
    r.text = text or (str(json_body) if json_body else "")
    if json_body is None:
        r.json.side_effect = ValueError("not json")
    else:
        r.json.return_value = json_body
    return r


def make_client():
    return RealFormerListClient(
        base_url="https://platform.socradar.com",
        api_key="test-key",
        company_id="1234567",
        actor_email="actor@company.com",
        list_path="/api/company/{company_id}/dark-web-monitoring/former-employees",
        add_path="/api/company/{company_id}/dark-web-monitoring/add-former-employee",
        remove_path="/api/company/{company_id}/dark-web-monitoring/delete-former-employee",
        batch_size=2,
    )


class TestRealClient(unittest.TestCase):
    def test_get_list_null_data(self):
        with mock.patch("actions.socradar_former.requests.get") as g:
            g.return_value = _resp(200, {"is_success": True, "response_code": 200, "data": None})
            self.assertEqual(make_client().get_list(), set())

    def test_get_list_objects(self):
        data = [{"id": 1, "email": "A@X.com", "name": "J", "surname": "D", "insert_date": "01-01-2026"},
                {"id": 2, "email": "b@y.com"}]
        with mock.patch("actions.socradar_former.requests.get") as g:
            g.return_value = _resp(200, {"is_success": True, "response_code": 200, "data": data})
            self.assertEqual(make_client().get_list(), {"a@x.com", "b@y.com"})

    def test_get_list_logical_error_raises(self):
        with mock.patch("actions.socradar_former.requests.get") as g:
            g.return_value = _resp(200, {"is_success": False, "response_code": 400, "data": None})
            with self.assertRaises(RuntimeError):
                make_client().get_list()

    def test_add_payload_and_batching(self):
        calls = []
        def fake_post(url, json=None, headers=None, timeout=None):
            calls.append((url, json, headers))
            return _resp(200, {"is_success": True, "response_code": 200, "data": None})
        with mock.patch("actions.socradar_former.requests.post", side_effect=fake_post):
            done = make_client().add(["e1@x.com", "e2@x.com", "e3@x.com"], source="elite-sync")
        self.assertEqual(done, 3)
        self.assertEqual(len(calls), 2)  # batch_size=2 -> 2+1
        url, body, headers = calls[0]
        self.assertIn("/api/company/1234567/dark-web-monitoring/add-former-employee", url)
        self.assertEqual(body, {"formerEmployees": ["e1@x.com", "e2@x.com"],
                                "comment": "elite-sync", "email": "actor@company.com"})
        # Cloudflare bot-block (preprod error 1010): an explicit UA is required, the default python UA is not enough
        self.assertEqual(headers.get("User-Agent"), "SOCRadar-EntraID-Elite/1.0")

    def test_add_logical_400_not_counted(self):
        with mock.patch("actions.socradar_former.requests.post") as p:
            p.return_value = _resp(200, {"is_success": False, "response_code": 400,
                                         "message": "'email' should be provided"})
            self.assertEqual(make_client().add(["e1@x.com"], source="s"), 0)

    def test_add_duplicate_rejection_counts_as_done(self):
        """Observed live (2026-08-01): re-adding a stored address
        returns is_success=false with this message. The desired state — address
        on the list — already holds, so it is done, not an error. Before this,
        every reconcile after the first successful add logged an ERROR forever,
        because the list endpoint reads back empty and the add is retried each
        run. The rejection is also the only readable proof the earlier add
        landed."""
        body = {"is_success": False, "response_code": 500,
                "message": "Employees already in database as former employee!"}
        with mock.patch("actions.socradar_former.requests.post") as p:
            p.return_value = _resp(200, body, text=str(body))
            self.assertEqual(make_client().add(["e1@x.com"], source="s"), 1)

    def test_remove_does_not_get_the_duplicate_leniency(self):
        """already_ok is an add-side rule; a remove failing with the same text
        would mean something genuinely wrong."""
        body = {"is_success": False, "response_code": 500,
                "message": "Employees already in database as former employee!"}
        with mock.patch("actions.socradar_former.requests.post") as p:
            p.return_value = _resp(200, body, text=str(body))
            self.assertEqual(make_client().remove(["e1@x.com"]), 0)

    def test_actor_rejection_is_still_a_failure(self):
        """The other observed is_success=false message must stay an error —
        a wrong actor means nothing was written."""
        body = {"is_success": False, "response_code": 400,
                "message": "User does not exist or does not belong to this company!"}
        with mock.patch("actions.socradar_former.requests.post") as p:
            p.return_value = _resp(200, body, text=str(body))
            self.assertEqual(make_client().add(["e1@x.com"], source="s"), 0)

    def test_remove_payload(self):
        calls = []
        def fake_post(url, json=None, headers=None, timeout=None):
            calls.append((url, json))
            return _resp(200, {"is_success": True, "response_code": 200, "data": None})
        with mock.patch("actions.socradar_former.requests.post", side_effect=fake_post):
            done = make_client().remove(["e1@x.com"])
        self.assertEqual(done, 1)
        self.assertEqual(calls[0][1], {"employeeEmails": ["e1@x.com"], "email": "actor@company.com"})

    def test_remove_404_html_treated_as_removed(self):
        with mock.patch("actions.socradar_former.requests.post") as p:
            p.return_value = _resp(404, None, text="<html>SOCRadar | 404</html>")
            self.assertEqual(make_client().remove(["gone@x.com"]), 1)

    def test_add_404_is_failure(self):
        # missing_ok applies to remove only — in add a 404 counts as an error
        with mock.patch("actions.socradar_former.requests.post") as p:
            p.return_value = _resp(404, None, text="<html>404</html>")
            self.assertEqual(make_client().add(["e@x.com"], source="s"), 0)


if __name__ == "__main__":
    unittest.main(verbosity=1)
