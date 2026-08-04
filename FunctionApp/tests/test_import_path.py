"""Import path (socradar_entra_id_import): checkpoint must not skip records."""

import sys
import types
import unittest
from importlib.machinery import ModuleSpec
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def _assert_window_not_written_off(test, save):
    """A held window means the finished-window marker was never written.

    "save was never called" used to state that, and no longer does: a held run
    now also persists consecutive_holds, so that a run holding on its very first
    pass can still arm the abandon escape. What has to stay true is narrower and
    is what these tests were always about — nothing recorded the window as done,
    so the next run reads it again.

    These callers all start from an empty checkpoint, so the guarantee takes its
    strongest form: no position may be written at all. Naming an expected date
    here instead would pass silently the day a fixture used a different one.
    """
    for call in save.call_args_list:
        test.assertNotIn(
            "last_start_date", call[0][3],
            "the window was written off despite a failure",
        )


def _ensure_azure_stub():
    """Make function_app importable outside the Function App image.

    The azure-* packages ship only in the worker image, which is why the import
    path had no tests at all. Sibling test modules install their own partial
    azure stubs and file order is not guaranteed, so fill in what is missing
    instead of replacing theirs.
    """
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

    def err(name):
        return type(name, (Exception,), {})

    class FunctionAppStub:
        def __init__(self, *a, **k):
            pass

        def timer_trigger(self, **_k):
            return lambda fn: fn

        def route(self, **_k):
            return lambda fn: fn

    class HttpResponseStub:
        def __init__(self, body="", status_code=200, mimetype=None, headers=None):
            self.body = body
            self.status_code = status_code
            self.mimetype = mimetype

        def get_body(self):
            return self.body.encode() if isinstance(self.body, str) else self.body

    fill("azure", is_package=True)
    fill("azure.core", is_package=True,
         MatchConditions=types.SimpleNamespace(IfNotModified="IfNotModified"))
    fill("azure.core.exceptions",
         ResourceNotFoundError=err("ResourceNotFoundError"),
         ResourceExistsError=err("ResourceExistsError"),
         ClientAuthenticationError=err("ClientAuthenticationError"),
         HttpResponseError=err("HttpResponseError"))
    fill("azure.data", is_package=True)
    fill("azure.data.tables", TableServiceClient=object, TableEntity=dict,
         UpdateMode=types.SimpleNamespace(REPLACE="replace", MERGE="merge"))
    fill("azure.identity", DefaultAzureCredential=object,
         ManagedIdentityCredential=object, ClientAssertionCredential=object)
    fill("azure.monitor", is_package=True)
    fill("azure.monitor.ingestion", LogsIngestionClient=object)
    fill("azure.functions", FunctionApp=FunctionAppStub,
         AuthLevel=types.SimpleNamespace(FUNCTION="function", ANONYMOUS="anonymous"),
         TimerRequest=object, HttpRequest=object, HttpResponse=HttpResponseStub)


_ensure_azure_stub()

import function_app  # noqa: E402


def _conf():
    return {
        "storage_account_name": "sa",
        "enable_user_lookup": False,
        "verified_domains": [],
        "enable_create_incident": False,
        "enable_resolve_alarm": False,
        "socradar_api_key": "k",
        "socradar_company_id": "1",
    }


def _employees(n, checkpoint):
    rows = [{"email": f"u{i}@example.com"} for i in range(n)]
    rows[-1]["_checkpoint_update"] = checkpoint
    return rows


class CheckpointAdvanceTest(unittest.TestCase):
    """The checkpoint describes the whole fetch. Saving it after an early exit
    would advance past records nobody processed — they are never fetched again."""

    DEADLINE = 1000.0

    def _run(self, budget_exhausted_after):
        ticks = iter(range(10_000))

        def fake_time():
            i = next(ticks)
            return self.DEADLINE + 1 if i >= budget_exhausted_after else 1.0

        with mock.patch.object(function_app.src_botnet, "fetch",
                               return_value=_employees(5, {"last_start_date": "2026-07-27"})), \
             mock.patch.object(function_app.cp, "load", return_value={}), \
             mock.patch.object(function_app.cp, "save") as save, \
             mock.patch.object(function_app.law, "write_records") as write, \
             mock.patch.object(function_app.time, "time", side_effect=fake_time):
            function_app._process_source("botnet", _conf(), None, {},
                                         deadline=self.DEADLINE, checkpoint_key="botnet:1")
        written = len(write.call_args[0][2]) if write.call_args else 0
        return written, save

    def test_checkpoint_held_back_when_budget_exhausted(self):
        written, save = self._run(budget_exhausted_after=2)
        self.assertLess(written, 5)   # the run really did stop early
        _assert_window_not_written_off(self, save)      # ...so the window must be re-fetched

    def test_checkpoint_saved_when_all_records_processed(self):
        written, save = self._run(budget_exhausted_after=10_000)
        self.assertEqual(written, 5)
        save.assert_called_once()
        saved = save.call_args[0][3]
        self.assertEqual(saved["last_start_date"], "2026-07-27")
        self.assertEqual(saved["consecutive_holds"], 0, "a clean run resets the hold count")


class EmptyAuditFieldsTest(unittest.TestCase):
    """_empty_audit must carry every field that write_audit reads, so a
    budget-skipped source is distinguishable from a genuine zero-record run."""

    def test_truncated_field_present_and_false_by_default(self):
        result = function_app._empty_audit("pii", "1", errors=0)
        self.assertIn("truncated", result)
        self.assertFalse(result["truncated"])

    def test_budget_exhaustion_marks_truncated(self):
        result = function_app._empty_audit("pii", "1", errors=0, truncated=True)
        self.assertTrue(result["truncated"])

    def test_capped_and_domain_filtered_present(self):
        result = function_app._empty_audit("botnet", "330", errors=1)
        self.assertIn("capped", result)
        self.assertIn("domain_filtered", result)
        self.assertFalse(result["capped"])
        self.assertEqual(result["domain_filtered"], 0)


if __name__ == "__main__":
    unittest.main()
