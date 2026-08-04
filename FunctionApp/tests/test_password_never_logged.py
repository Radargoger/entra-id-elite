"""Where the leaked credential is allowed to go, and where it is not.

The credential is recorded as SOCRadar delivered it: masked or in the clear is
decided per company on the platform, upstream of this app. That is deliberate,
and one column carries it. Everywhere else it must not appear, and a log line
is the easiest place for it to escape unnoticed.

These tests are written against behaviour rather than field names, so renaming
a field cannot quietly move the credential somewhere new.
"""

import logging
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from test_import_path import _ensure_azure_stub  # noqa: E402

_ensure_azure_stub()

from actions import law_writer  # noqa: E402
from utils import sanitize  # noqa: E402

SECRET = "Zm4rQ7-unmistakable-Ww91"


class TheCredentialReachesExactlyOneColumn(unittest.TestCase):

    def test_it_is_carried_in_the_password_column(self):
        fields = sanitize.build_law_password_fields(sanitize.sanitize_password(SECRET))
        carrying = [k for k, v in fields.items() if v == SECRET]
        self.assertEqual(carrying, ["password"],
                         f"the credential appears in {carrying}, expected only 'password'")

    def test_the_masked_column_never_carries_it(self):
        fields = sanitize.build_law_password_fields(sanitize.sanitize_password(SECRET))
        self.assertNotIn(SECRET, str(fields["password_masked"]))
        self.assertNotIn(SECRET[2:-2], str(fields["password_masked"]),
                         "even a slice of the credential is too much for a dashboard")

    def test_a_record_written_to_log_analytics_carries_it_once(self):
        conf = {"dcr_immutable_id": "d", "dcr_endpoint": "https://x.invalid",
                "socradar_company_id": "1234567"}
        record = {"email": "a@x.com", "password": SECRET, "password_masked": "Z***1"}

        with mock.patch.object(law_writer, "_upload", return_value=True) as up:
            law_writer.write_records(conf, "botnet", [record])

        sent = up.call_args[0][2][0]
        holders = [k for k, v in sent.items() if isinstance(v, str) and SECRET in v]
        self.assertEqual(holders, ["password"],
                         f"the credential also reached {holders}")


class TheCredentialNeverReachesTheLogs(unittest.TestCase):
    """A log line goes to Application Insights, which has different retention
    and different access than the workspace table, so the credential must not
    ride along in one."""

    def _captured_logs(self, fn):
        buffer = []

        class _Catch(logging.Handler):
            def emit(self, record):
                try:
                    buffer.append(record.getMessage())
                except Exception:
                    buffer.append(str(record.msg))
                buffer.append(str(record.args))

        root = logging.getLogger()
        handler = _Catch()
        root.addHandler(handler)
        previous = root.level
        root.setLevel(logging.DEBUG)
        try:
            fn()
        finally:
            root.removeHandler(handler)
            root.setLevel(previous)
        return "\n".join(buffer)

    def test_sanitising_a_credential_logs_nothing_about_it(self):
        text = self._captured_logs(lambda: sanitize.sanitize_password(SECRET))
        self.assertNotIn(SECRET, text)

    def test_writing_a_record_logs_nothing_about_it(self):
        conf = {"dcr_immutable_id": "d", "dcr_endpoint": "https://x.invalid",
                "socradar_company_id": "1234567"}
        record = {"email": "a@x.com", "password": SECRET}

        def write():
            with mock.patch.object(law_writer, "_upload", return_value=True):
                law_writer.write_records(conf, "botnet", [record])

        self.assertNotIn(SECRET, self._captured_logs(write))

    def test_a_failed_write_logs_nothing_about_it(self):
        """The error path is the one that tends to print the whole payload."""
        conf = {"dcr_immutable_id": "d", "dcr_endpoint": "https://x.invalid",
                "socradar_company_id": "1234567"}
        record = {"email": "a@x.com", "password": SECRET}

        def write():
            with mock.patch.object(law_writer, "_upload",
                                   side_effect=RuntimeError("ingestion refused")):
                try:
                    law_writer.write_records(conf, "botnet", [record])
                except RuntimeError:
                    pass

        self.assertNotIn(SECRET, self._captured_logs(write))


REPO_MODULES = {"function_app", "actions", "sources", "utils",
                "test_import_path", "test_action_gates", "test_leak_probe"}

REPO_ARTEFACTS = ("azuredeploy.json", "main.bicep",
                  "createUiDefinition.json", "requirements.txt")


def _is_coupled(source: str) -> bool:
    """True when this test source can be made to fail by the app changing.

    Three ways to qualify: import an app module, read a named app file, or walk
    the app's own Python sources (the UTC convention guard does the last one,
    and is coupled to every module at once).
    """
    import ast

    imports = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imports |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
    if imports & REPO_MODULES:
        return True
    if any(artefact in source for artefact in REPO_ARTEFACTS):
        return True
    return 'rglob("*.py")' in source and "parents[2]" in source


class EveryTestFileIsCoupledToTheRepository(unittest.TestCase):
    """A test that touches nothing in the repository cannot fail when the
    repository breaks. One such file sat here green for weeks, asserting facts
    about the standard library and nothing else.
    """

    def test_no_test_file_stands_on_its_own(self):
        tests = Path(__file__).resolve().parent
        orphans = [path.name for path in sorted(tests.glob("test_*.py"))
                   if not _is_coupled(path.read_text())]
        self.assertEqual(orphans, [],
                         "these neither import an app module nor read an app "
                         "file, so nothing in the app can make them fail")

    def test_an_uncoupled_file_is_actually_rejected(self):
        """The check above passes when every file qualifies -- including when
        the rule has been loosened to accept anything. Mutation testing found
        exactly that hole: replacing the walk clause with `if True` left the
        suite green. A file that must be refused closes it."""
        orphan = ("import unittest\n"
                  "class T(unittest.TestCase):\n"
                  "    def test_math(self):\n"
                  "        self.assertEqual(1 + 1, 2)\n")
        self.assertFalse(_is_coupled(orphan),
                         "the coupling rule accepts a file that touches "
                         "nothing in the app")

    def test_each_coupling_form_is_recognised(self):
        self.assertTrue(_is_coupled("from actions import law_writer\n"))
        self.assertTrue(_is_coupled('P = "deploy/azuredeploy.json"\n'))
        self.assertTrue(_is_coupled(
            'R = Path(__file__).resolve().parents[2]\n'
            'for p in R.rglob("*.py"):\n    pass\n'))


if __name__ == "__main__":
    unittest.main()
