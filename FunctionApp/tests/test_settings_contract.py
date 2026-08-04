"""The template and the code have to agree on the settings between them.

A name the code reads and the template never writes falls back to a default,
quietly. A timer whose schedule token is missing does not fire at all. Neither
shows up as an error anywhere, so this file compares the two sides directly.

It reads files and nothing else: no app import, no Azure stub, no network.
"""

import ast
import json
import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
TEMPLATE = REPO / "deploy" / "azuredeploy.json"
CONFIG = REPO / "FunctionApp" / "utils" / "config.py"
FUNCTION_APP = REPO / "FunctionApp" / "function_app.py"

# Timer schedules resolved by the Functions host, not by Python. The app has no
# code path that supplies a fallback: an unset token means the trigger never
# fires and the host says nothing about it.
BINDING_TOKENS = {"POLLING_SCHEDULE", "FORMER_SYNC_SCHEDULE"}

# Settings config.load() refuses to start without. Conditional ones
# (FORMER_ACTOR_EMAIL, FORMER_API_KEY) are excluded on purpose: they are only
# required when no company map is configured, and the template always writes
# one.
ALWAYS_REQUIRED = {
    "SOCRADAR_API_KEY",
    "SOCRADAR_COMPANY_ID",
    "DCR_IMMUTABLE_ID",
    "DCR_ENDPOINT",
    "STORAGE_ACCOUNT_NAME",
    "ENTRA_CLIENT_ID",
}


def _template():
    return json.loads(TEMPLATE.read_text())


def _function_app_settings():
    """Names written into the Function App's own configuration.

    Deployment scripts carry their own environment variables (APP_ID, RG_NAME
    and friends). Those never reach the running app, so counting them here
    would make the contract look satisfied when it is not.
    """
    template = _template()
    resources = template["resources"]
    resources = resources.values() if isinstance(resources, dict) else resources

    names = set()
    for res in resources:
        if "Microsoft.Web/sites" not in str(res.get("type", "")):
            continue
        text = json.dumps(res)
        names |= set(re.findall(r"createObject\('name',\s*'([A-Z][A-Z0-9_]{2,})'", text))
        names |= set(re.findall(r'"name":\s*"([A-Z][A-Z0-9_]{2,})"', text))
    return names


class TheTemplateSuppliesWhatTheCodeNeeds(unittest.TestCase):

    def test_every_timer_schedule_token_is_written(self):
        missing = BINDING_TOKENS - _function_app_settings()
        self.assertEqual(missing, set(),
                         "the host cannot resolve these, so the timer never fires")

    def test_the_tokens_listed_here_are_the_ones_the_code_uses(self):
        used = set(re.findall(r'"%([A-Z_]{3,})%"', FUNCTION_APP.read_text()))
        self.assertEqual(used, BINDING_TOKENS,
                         "a binding token was added or removed; update this list "
                         "and make sure the template writes it")

    def test_every_required_setting_is_written(self):
        missing = ALWAYS_REQUIRED - _function_app_settings()
        self.assertEqual(missing, set(),
                         "config.load() raises without these, so the app cannot start")

    def test_the_required_list_matches_the_code(self):
        """Guards the list above: a new required=True setting must be added here
        and, through the previous test, written by the template."""
        found = set(re.findall(r'_get\(\s*"([A-Z][A-Z0-9_]+)"\s*,\s*required=True',
                               CONFIG.read_text()))
        self.assertEqual(found, ALWAYS_REQUIRED,
                         "unconditionally required settings changed in config.py")


class TheAppReadsItsSettingsInOnePlace(unittest.TestCase):
    """Settings read at import time cannot be changed without a restart and are
    invisible to config.load(), so they drift from the template unnoticed."""

    # Two justified exceptions:
    #
    # function_app.py reads RUN_ON_STARTUP and FORMER_RUN_ON_STARTUP into the
    # timer decorators. A decorator argument is evaluated when the module is
    # imported, so there is no later point at which config.load() could supply
    # it. This one has to stay.
    #
    # base_fetcher.py reads MAX_PAGES_PER_RUN at import, but every call site
    # passes the value from conf and falls back to the constant only when conf
    # has none. Recorded rather than removed: taking it out changes behaviour,
    # and the fallback is reachable only from tests.
    KNOWN_MODULE_LEVEL_READS = {"function_app.py", "sources/base_fetcher.py"}

    def test_no_new_module_level_env_read_appears(self):
        offenders = set()
        for path in (REPO / "FunctionApp").rglob("*.py"):
            rel = path.relative_to(REPO / "FunctionApp").as_posix()
            if rel.startswith("tests/") or "__pycache__" in rel:
                continue
            if rel == "utils/config.py":
                continue
            tree = ast.parse(path.read_text())
            for node in tree.body:  # module level only
                if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                    continue
                for call in ast.walk(node):
                    if not isinstance(call, ast.Call):
                        continue
                    attr = getattr(call.func, "attr", "")
                    if attr in ("getenv", "get") and "environ" in ast.dump(call.func):
                        offenders.add(rel)
                    elif attr == "getenv":
                        offenders.add(rel)
        self.assertEqual(
            offenders, self.KNOWN_MODULE_LEVEL_READS,
            "read settings through utils/config.py so the template and the app "
            "stay in step, or add a justified entry to KNOWN_MODULE_LEVEL_READS")


class ThePackageTheTemplateShipsIsPinned(unittest.TestCase):
    """The deploy button serves this template straight from master, so the URL
    in it is what customers actually download."""

    def test_the_package_points_at_the_shared_release(self):
        uri = _template()["parameters"]["PackageUri"]["defaultValue"]
        self.assertTrue(uri.endswith("/releases/download/v1.0.0/FunctionApp.zip"),
                        f"the shared build is always v1.0.0, found: {uri}")


if __name__ == "__main__":
    unittest.main()
