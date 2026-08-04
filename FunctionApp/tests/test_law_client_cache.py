"""The cached ingestion client, which nothing tested until it nearly broke.

While reshaping this cache into a single (endpoint, client) pair, an early
version returned the pair instead of the client. Every audit write would then
have called .upload() on a tuple, the exception handler would have swallowed it,
and the product's whole audit trail would have gone quiet while the run
reported an ingestion failure and held its checkpoint.

That version passed all 329 tests. It was caught by reading, not by the suite,
so these are the tests that would have caught it: the returned object has to be
usable, the endpoint has to be honoured, and a failed build must not poison the
cache for the next call.
"""

import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from test_import_path import _ensure_azure_stub  # noqa: E402

_ensure_azure_stub()

from actions import law_writer  # noqa: E402

ENDPOINT_A = "https://dcr-a.ingest.monitor.azure.com"
ENDPOINT_B = "https://dcr-b.ingest.monitor.azure.com"


class _FakeClient:
    def __init__(self, endpoint):
        self.endpoint = endpoint
        self.uploads = []

    def upload(self, rule_id, stream_name, logs):
        self.uploads.append((rule_id, stream_name, len(logs)))


class TheCachedClientIsUsable(unittest.TestCase):

    def setUp(self):
        law_writer._client = None

    def tearDown(self):
        law_writer._client = None

    def _patched(self, built):
        def make(endpoint, credential):
            client = _FakeClient(endpoint)
            built.append(endpoint)
            return client
        return mock.patch.object(law_writer, "LogsIngestionClient",
                                 side_effect=make)

    def test_what_comes_back_can_actually_upload(self):
        """The caller does client.upload(...) straight away. Returning the
        store instead of its client passes any test that only checks for
        not-None."""
        built = []
        with self._patched(built), \
             mock.patch.object(law_writer, "DefaultAzureCredential",
                               lambda *a, **k: object()):
            client = law_writer._get_client(ENDPOINT_A)
        self.assertTrue(hasattr(client, "upload"),
                        f"got {type(client).__name__}, which the upload path "
                        f"cannot call .upload() on")
        client.upload(rule_id="r", stream_name="s", logs=[{}])
        self.assertEqual(client.uploads, [("r", "s", 1)])

    def test_the_same_endpoint_reuses_one_client(self):
        built = []
        with self._patched(built), \
             mock.patch.object(law_writer, "DefaultAzureCredential",
                               lambda *a, **k: object()):
            first = law_writer._get_client(ENDPOINT_A)
            second = law_writer._get_client(ENDPOINT_A)
        self.assertIs(first, second)
        self.assertEqual(built, [ENDPOINT_A], "built a second client needlessly")

    def test_a_different_endpoint_gets_its_own_client(self):
        """Nothing in this deployment changes the endpoint today, but a cache
        that ignores it would send one workspace's rows to another."""
        built = []
        with self._patched(built), \
             mock.patch.object(law_writer, "DefaultAzureCredential",
                               lambda *a, **k: object()):
            first = law_writer._get_client(ENDPOINT_A)
            second = law_writer._get_client(ENDPOINT_B)
        self.assertIsNot(first, second)
        self.assertEqual(second.endpoint, ENDPOINT_B,
                         "the cached client was reused for a different endpoint")
        self.assertEqual(built, [ENDPOINT_A, ENDPOINT_B])

    def test_the_store_keeps_the_endpoint_with_its_client(self):
        built = []
        with self._patched(built), \
             mock.patch.object(law_writer, "DefaultAzureCredential",
                               lambda *a, **k: object()):
            law_writer._get_client(ENDPOINT_A)
        endpoint, client = law_writer._client
        self.assertEqual(endpoint, client.endpoint,
                         "the store names one endpoint and holds a client for "
                         "another")

    def test_a_failed_build_returns_none_and_leaves_the_cache_alone(self):
        with mock.patch.object(law_writer, "LogsIngestionClient",
                               side_effect=RuntimeError("no credential")), \
             mock.patch.object(law_writer, "DefaultAzureCredential",
                               lambda *a, **k: object()):
            self.assertIsNone(law_writer._get_client(ENDPOINT_A))
        self.assertIsNone(law_writer._client,
                          "a failed build left something in the cache")

    def test_a_failure_does_not_stop_the_next_attempt_succeeding(self):
        built = []
        with mock.patch.object(law_writer, "DefaultAzureCredential",
                               lambda *a, **k: object()):
            with mock.patch.object(law_writer, "LogsIngestionClient",
                                   side_effect=RuntimeError("transient")):
                self.assertIsNone(law_writer._get_client(ENDPOINT_A))
            with self._patched(built):
                client = law_writer._get_client(ENDPOINT_A)
        self.assertTrue(hasattr(client, "upload"))


class AnUploadUsesTheClientItWasGiven(unittest.TestCase):
    """_upload is the only consumer, so the contract is checked end to end."""

    def setUp(self):
        law_writer._client = None

    def tearDown(self):
        law_writer._client = None

    def test_a_record_reaches_the_client(self):
        captured = _FakeClient(ENDPOINT_A)
        with mock.patch.object(law_writer, "_get_client",
                               return_value=captured):
            ok = law_writer._upload("rule-1", "Custom-Test_CL",
                                    [{"a": 1}], ENDPOINT_A)
        self.assertTrue(ok)
        self.assertEqual(captured.uploads, [("rule-1", "Custom-Test_CL", 1)])

    def test_no_client_means_no_silent_success(self):
        with mock.patch.object(law_writer, "_get_client", return_value=None):
            self.assertFalse(law_writer._upload("r", "s", [{}], ENDPOINT_A))


if __name__ == "__main__":
    unittest.main()
