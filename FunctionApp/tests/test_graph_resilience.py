"""Graph resilience: credential binding under two timers, throttle retry."""

import sys
import types
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from actions import entra_id  # noqa: E402
from sources import entra_users  # noqa: E402


def _credential_for(tenant):
    cred = types.SimpleNamespace()
    cred.get_token = lambda _scope: types.SimpleNamespace(token=f"token-{tenant}")
    return cred


class GraphCredentialBindingTest(unittest.TestCase):
    """A Graph token must belong to the tenant that was asked for.

    This is the product's core isolation guarantee: one company's leak run must
    never look up, or act on, another company's directory. Nothing on the
    permission side enforces it, because the sibling tenant has consented the
    same multi-tenant app. It holds only if this function is right.
    """

    def setUp(self):
        entra_id._graph_credential = None

    def tearDown(self):
        entra_id._graph_credential = None

    def test_a_retarget_during_the_key_comparison_is_not_used(self):
        """A key whose comparison swaps the store mid-call must not change the
        answer. This window was already closed; it is kept so a rewrite cannot
        reopen it."""

        class RetargetingKey(tuple):
            def __ne__(self, other):
                # The other timer finishes its own build right here.
                entra_id._graph_credential = (("intruder", "client-1"),
                                              _credential_for("intruder"))
                return False  # same key: take the cache-hit path

            def __eq__(self, other):
                return True

            __hash__ = tuple.__hash__

        entra_id._graph_credential = (RetargetingKey(("tenant-a", "client-1")),
                                      _credential_for("tenant-a"))

        token = entra_id.get_graph_token("tenant-a", "client-1")

        self.assertEqual(token, "token-tenant-a")

    def test_the_stored_key_always_names_the_stored_credential(self):
        """The invariant, stated as the thing that can actually go wrong.

        An earlier version of this test asserted that the two used to be
        separate globals and now are one tuple. That caught a literal revert
        and nothing else: an independent review built a variant that keeps one
        tuple but publishes it holding the PREVIOUS key, passed the whole suite
        with it, and showed it handing tenant A a tenant B token.

        So the assertion is now on the pairing itself. Every credential this
        module hands out is tagged with the tenant it was built for, and after
        any sequence of calls the stored key has to name the stored credential.
        """
        def tagged_build(tenant_id, client_id):
            cred = _credential_for(tenant_id)
            cred.built_for = (tenant_id, client_id)
            return cred

        with mock.patch.object(entra_id, "_build_graph_credential",
                               side_effect=tagged_build):
            for tenant in ("tenant-a", "tenant-b", "tenant-a", "tenant-c"):
                token = entra_id.get_graph_token(tenant, "client-1")
                self.assertEqual(token, f"token-{tenant}",
                                 f"asked {tenant}, got {token}")
                key, credential = entra_id._graph_credential
                self.assertEqual(
                    key, credential.built_for,
                    f"store says {key} but holds a credential built for "
                    f"{credential.built_for}; a reader taking the cache-hit "
                    f"path would act on the wrong tenant")

    def test_interleaved_tenants_each_get_their_own_token(self):
        """Two timers and the preview endpoints all reach this function. Each
        caller must come away with the tenant it asked for, whatever order the
        calls arrive in."""
        import threading

        def tagged_build(tenant_id, client_id):
            return _credential_for(tenant_id)

        wrong = []
        barrier = threading.Barrier(4)

        def ask(tenant):
            barrier.wait()
            for _ in range(40):
                token = entra_id.get_graph_token(tenant, "client-1")
                if token != f"token-{tenant}":
                    wrong.append((tenant, token))

        with mock.patch.object(entra_id, "_build_graph_credential",
                               side_effect=tagged_build):
            threads = [threading.Thread(target=ask, args=(t,))
                       for t in ("tenant-a", "tenant-b", "tenant-c", "tenant-d")]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

        self.assertEqual(wrong, [], "a caller was handed another tenant's token")

    def test_asking_for_another_tenant_never_returns_the_cached_token(self):
        """The cache is keyed, so a second company asking gets its own token
        rather than whatever the previous company left behind."""
        built = []

        def fake_build(tenant_id, client_id):
            built.append(tenant_id)
            return _credential_for(tenant_id)

        with mock.patch.object(entra_id, "_build_graph_credential",
                               side_effect=fake_build):
            first = entra_id.get_graph_token("tenant-a", "client-1")
            second = entra_id.get_graph_token("tenant-b", "client-1")
            third = entra_id.get_graph_token("tenant-a", "client-1")

        self.assertEqual(first, "token-tenant-a")
        self.assertEqual(second, "token-tenant-b",
                         "company B was handed company A's token")
        self.assertEqual(third, "token-tenant-a",
                         "company A was handed company B's token")
        self.assertEqual(built, ["tenant-a", "tenant-b", "tenant-a"])

    def test_cached_credential_reused_for_same_key(self):
        calls = []

        def build(tenant_id, client_id):
            calls.append((tenant_id, client_id))
            cred = types.SimpleNamespace()
            cred.get_token = lambda _scope: types.SimpleNamespace(token="cached")
            return cred

        with mock.patch.object(entra_id, "_build_graph_credential", side_effect=build):
            entra_id.get_graph_token("tenant-a", "client-1")
            entra_id.get_graph_token("tenant-a", "client-1")

        self.assertEqual(len(calls), 1)


class _Resp:
    def __init__(self, status, payload=None, headers=None, text=""):
        self.status_code = status
        self._payload = payload or {}
        self.headers = headers or {}
        self.text = text

    def json(self):
        return self._payload


class ThrottleRetryTest(unittest.TestCase):
    """A 429 must not be reported as missing data — that would mark the
    snapshot incomplete and block the reconcile."""

    def test_429_then_success(self):
        responses = [
            _Resp(429, headers={"Retry-After": "1"}),
            _Resp(200, {"value": [{"id": "u1"}]}),
        ]
        with mock.patch.object(entra_users.requests, "get", side_effect=responses) as get, \
             mock.patch.object(entra_users.time, "sleep") as sleep:
            items = entra_users._get_paged(
                "https://graph.microsoft.com/v1.0/users", {"Authorization": "x"}
            )

        self.assertEqual(items, [{"id": "u1"}])
        self.assertEqual(get.call_count, 2)
        sleep.assert_called_once_with(1)

    def test_503_retried_then_raises_after_budget(self):
        responses = [_Resp(503, text="busy")] * (entra_users._THROTTLE_RETRIES + 1)
        with mock.patch.object(entra_users.requests, "get", side_effect=responses), \
             mock.patch.object(entra_users.time, "sleep"):
            with self.assertRaises(RuntimeError):
                entra_users._get_paged(
                    "https://graph.microsoft.com/v1.0/users", {"Authorization": "x"}
                )

    def test_403_raises_immediately(self):
        with mock.patch.object(entra_users.requests, "get",
                               side_effect=[_Resp(403, text="denied")]) as get, \
             mock.patch.object(entra_users.time, "sleep") as sleep:
            with self.assertRaises(RuntimeError):
                entra_users._get_paged(
                    "https://graph.microsoft.com/v1.0/users", {"Authorization": "x"}
                )

        self.assertEqual(get.call_count, 1)
        sleep.assert_not_called()

    def test_foreign_nextlink_still_rejected(self):
        with mock.patch.object(entra_users.requests, "get") as get:
            with self.assertRaises(RuntimeError):
                entra_users._get_paged("https://evil.example.com/v1.0/users", {})
        get.assert_not_called()


if __name__ == "__main__":
    unittest.main()
