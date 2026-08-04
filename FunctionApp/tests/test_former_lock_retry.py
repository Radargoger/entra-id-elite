"""
Single-writer lease + bounded client retry tests (hardening).
"""
import os
import sys
import time
import types
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Stub the azure imports (same pattern as test_real_client.py — the InMemory
# lock and _send are pure and never touch the azure SDK).
azure_pkg = types.ModuleType("azure")
tables_mod = types.ModuleType("azure.data.tables")
tables_mod.TableServiceClient = object
tables_mod.TableEntity = dict
core_mod = types.ModuleType("azure.core.exceptions")
core_mod.ResourceNotFoundError = type("ResourceNotFoundError", (Exception,), {})
core_mod.ResourceExistsError = type("ResourceExistsError", (Exception,), {})
sys.modules.setdefault("azure", azure_pkg)
sys.modules.setdefault("azure.data.tables", tables_mod)
sys.modules.setdefault("azure.core.exceptions", core_mod)

from actions.former_lock import InMemoryLeaseLock
from actions.socradar_former import RealFormerListClient


class LeaseLockTests(unittest.TestCase):

    def setUp(self):
        InMemoryLeaseLock._locks.clear()

    def test_acquire_then_conflict(self):
        a = InMemoryLeaseLock("1234567", holder="timer")
        b = InMemoryLeaseLock("1234567", holder="manual")
        self.assertTrue(a.acquire())
        self.assertFalse(b.acquire())  # held -> second writer refused

    def test_different_companies_independent(self):
        a = InMemoryLeaseLock("1234567", holder="timer")
        b = InMemoryLeaseLock("440", holder="timer")
        self.assertTrue(a.acquire())
        self.assertTrue(b.acquire())

    def test_release_frees_lease(self):
        a = InMemoryLeaseLock("1234567", holder="timer")
        b = InMemoryLeaseLock("1234567", holder="manual")
        a.acquire()
        a.release()
        self.assertTrue(b.acquire())

    def test_expired_lease_taken_over(self):
        a = InMemoryLeaseLock("1234567", holder="crashed", ttl_seconds=0)
        a.acquire()
        time.sleep(0.01)  # lease with ttl=0 expires immediately
        b = InMemoryLeaseLock("1234567", holder="timer")
        self.assertTrue(b.acquire())  # expiry is the crash backstop

    def test_release_by_non_holder_keeps_lease(self):
        a = InMemoryLeaseLock("1234567", holder="timer")
        a.acquire()
        b = InMemoryLeaseLock("1234567", holder="manual")
        b.release()  # never acquired -> must not free a's lease
        c = InMemoryLeaseLock("1234567", holder="other")
        self.assertFalse(c.acquire())


class _FakeResp:
    def __init__(self, status):
        self.status_code = status
        self.text = ""


class RetryTests(unittest.TestCase):

    def _client(self):
        return RealFormerListClient(
            base_url="https://x.invalid", api_key="k", company_id="1234567",
            actor_email="a@x.com", list_path="/l", add_path="/a", remove_path="/r")

    def test_transient_500_retried_once_then_returned(self):
        calls = []
        def fn():
            calls.append(1)
            return _FakeResp(500 if len(calls) == 1 else 200)
        resp = self._client()._send(fn)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(calls), 2)

    def test_permanent_400_not_retried(self):
        calls = []
        def fn():
            calls.append(1)
            return _FakeResp(400)
        resp = self._client()._send(fn)
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(len(calls), 1)

    def test_retry_is_bounded_two_attempts_max(self):
        calls = []
        def fn():
            calls.append(1)
            return _FakeResp(503)
        resp = self._client()._send(fn)
        self.assertEqual(resp.status_code, 503)  # still surfaced, never looped
        self.assertEqual(len(calls), 2)

    def test_add_retry_deduped_when_first_post_committed(self):
        # Adversary 2026-07-25: a POST that commits then 500s must not be
        # blindly re-POSTed (duplicate risk if the API appends). The retry
        # hook re-reads the list; fully-present chunk cancels the retry.
        from unittest import mock
        client = self._client()
        ok = mock.Mock(status_code=200)
        ok.json.return_value = {"is_success": True, "response_code": 200,
                                "data": [{"email": "a@x.com"}, {"email": "b@x.com"}]}
        with mock.patch("actions.socradar_former.requests.post",
                        return_value=_FakeResp(500)) as post, \
             mock.patch("actions.socradar_former.requests.get", return_value=ok):
            done = client.add(["a@x.com", "b@x.com"], source="t")
        self.assertEqual(done, 2)            # both confirmed via readback
        self.assertEqual(post.call_count, 1)  # NO second POST

    def test_add_retry_sends_only_missing_remainder(self):
        from unittest import mock
        client = self._client()
        listing = mock.Mock(status_code=200)
        listing.json.return_value = {"is_success": True, "response_code": 200,
                                     "data": [{"email": "a@x.com"}]}  # only a@ landed
        ok_post = mock.Mock(status_code=200)
        ok_post.json.return_value = {"is_success": True, "response_code": 200}
        with mock.patch("actions.socradar_former.requests.post",
                        side_effect=[_FakeResp(502), ok_post]) as post, \
             mock.patch("actions.socradar_former.requests.get", return_value=listing):
            done = client.add(["a@x.com", "b@x.com"], source="t")
        self.assertEqual(done, 2)  # 1 readback-confirmed + 1 retried
        self.assertEqual(post.call_count, 2)
        retry_body = post.call_args_list[1].kwargs["json"]
        self.assertEqual(retry_body["formerEmployees"], ["b@x.com"])  # remainder only


if __name__ == "__main__":
    unittest.main()
