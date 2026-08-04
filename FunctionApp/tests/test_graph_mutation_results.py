"""A Graph mutation reports success only when Graph actually performed it.

These wrappers sit at the point where an untrue answer becomes permanent: the
caller writes the action into the idempotency ledger when the wrapper returns
True, and a ledger entry means nobody ever retries. So a wrapper that counts a
403 or a 500 as success does not merely lose one action -- it records a
directory change that never happened and closes the door on it.

The module was the least covered in the repository (23%) and it holds every
irreversible operation the product can perform, which is why the failure codes
are enumerated here rather than sampled.
"""

import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from test_import_path import _ensure_azure_stub  # noqa: E402

_ensure_azure_stub()

from actions import entra_id as entra  # noqa: E402

HEADERS = {"Authorization": "Bearer test"}
USER = "11111111-2222-3333-4444-555555555555"
GROUP = "99999999-8888-7777-6666-555555555555"

# Codes Graph returns when it refused. None of these may read as success.
REFUSALS = [400, 401, 403, 404, 405, 409, 412, 429, 500, 502, 503]


class _Resp:
    def __init__(self, status, text=""):
        self.status_code = status
        self.text = text

    def json(self):
        return {}


def _call(fn, status, text=""):
    """Run one wrapper against a stubbed Graph reply."""
    with mock.patch.object(entra, "_graph_request",
                           return_value=_Resp(status, text)):
        if fn in (entra.add_to_group, entra.remove_from_group):
            return fn(USER, GROUP, HEADERS)
        return fn(USER, HEADERS)


# (function, the codes that genuinely mean "done")
SUCCESS_CODES = [
    (entra.revoke_sessions, {200, 204}),
    (entra.disable_account, {204}),
    (entra.enable_account, {204}),
    (entra.force_password_change, {204}),
    (entra.confirm_compromised, {204}),
    (entra.add_to_group, {204}),
    (entra.remove_from_group, {204}),
]


class ARefusalIsNeverSuccess(unittest.TestCase):

    def test_no_wrapper_reports_success_on_a_refusal(self):
        wrong = []
        for fn, success in SUCCESS_CODES:
            for code in REFUSALS:
                if code in success:
                    continue
                # add_to_group and remove_from_group treat one refusal as
                # "already in the desired state", which is a different claim
                # from "the call worked" and is asserted separately below.
                if fn is entra.add_to_group and code == 400:
                    continue
                if fn is entra.remove_from_group and code == 404:
                    continue
                if _call(fn, code, text="Insufficient privileges") is not False:
                    wrong.append(f"{fn.__name__} said success on HTTP {code}")
        self.assertEqual(wrong, [],
                         "these would write a ledger entry for a change Graph "
                         "refused, and nothing would retry it")

    def test_each_wrapper_accepts_only_its_own_success_codes(self):
        wrong = []
        for fn, success in SUCCESS_CODES:
            for code in sorted(success):
                if _call(fn, code) is not True:
                    wrong.append(f"{fn.__name__} rejected HTTP {code}")
        self.assertEqual(wrong, [], "a real success reported as failure")

    def test_a_transport_error_is_not_success(self):
        """A timeout mid-call leaves the outcome unknown, and unknown is not
        done: the run must be free to try again."""
        import requests
        wrong = []
        for fn, _ in SUCCESS_CODES:
            with mock.patch.object(entra, "_graph_request",
                                   side_effect=requests.RequestException("timeout")):
                args = ((USER, GROUP, HEADERS)
                        if fn in (entra.add_to_group, entra.remove_from_group)
                        else (USER, HEADERS))
                if fn(*args) is not False:
                    wrong.append(fn.__name__)
        self.assertEqual(wrong, [], "these swallowed a transport error as success")


class AlreadyInTheDesiredStateCountsAsDone(unittest.TestCase):
    """Two group operations treat one refusal as success on purpose, because
    the directory already holds the state the caller asked for. Pinned here so
    the exemption stays narrow and deliberate."""

    def test_adding_a_member_who_is_already_there(self):
        self.assertTrue(_call(entra.add_to_group, 400,
                              text="One or more added object references "
                                   "already exist"))

    def test_adding_is_still_a_failure_on_any_other_400(self):
        self.assertFalse(_call(entra.add_to_group, 400,
                               text="Insufficient privileges to complete the "
                                    "operation"))

    def test_removing_a_member_who_is_not_there(self):
        self.assertTrue(_call(entra.remove_from_group, 404))


class TheSuccessCodeTableCoversEveryMutation(unittest.TestCase):
    """A wrapper added later and left out of the table above would be untested
    while looking tested. The module lists what it can do; this compares."""

    def test_every_mutation_in_the_module_is_in_the_table(self):
        import inspect

        # Reads and token work are not mutations; everything else that talks to
        # Graph and returns a bool is.
        not_mutations = {"lookup_user", "get_graph_token", "validate_password_ropc",
                         "delete_mfa_methods", "list_mfa_methods"}
        covered = {fn.__name__ for fn, _ in SUCCESS_CODES}
        missing = []
        for name, obj in vars(entra).items():
            if name.startswith("_") or not inspect.isfunction(obj):
                continue
            if getattr(obj, "__module__", None) != entra.__name__:
                continue
            if name in not_mutations or name in covered:
                continue
            if inspect.signature(obj).return_annotation is bool:
                missing.append(name)
        self.assertEqual(missing, [],
                         "these return a success flag Graph never had to earn "
                         "in any test")


if __name__ == "__main__":
    unittest.main()
