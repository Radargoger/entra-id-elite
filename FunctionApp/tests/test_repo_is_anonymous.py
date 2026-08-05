"""No tracked file names a real account, person, tenant or directory object.

An external review of a downstream copy found what our own scans had missed:
a real company id used as the fixture id everywhere, a real enterprise named
in a test docstring, a display name lifted from a captured feed, a real
directory objectId and the first block of a real tenant GUID. None of these
is a credential, which is exactly why the secret scan and the language scan
both walked past them.

Every forbidden literal below is written in two pieces so this file cannot
match itself. The digit ids are matched only when they stand alone as a
number (no digit on either side), so values like 1440 stay legal.
"""

import re
import subprocess
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

# Real ids that once lived here as fixtures: the internal company id of the
# test account and its two siblings from the same internal example. Written
# split so this file cannot match itself.
_REAL_COMPANY_IDS = re.compile(r"(?<![0-9])(3" "30|4" "40|5" "50)(?![0-9])")

# Substrings that identify a real entity wherever they appear.
_FORBIDDEN = [
    "voda" "fone",           # enterprise named in an internal design example
    "Emma " "Taylor",        # display name from a captured VIP feed record
    "c5f5" "dcec",           # real directory objectId (prefix suffices)
    "20e3" "7d41",           # first block of a real tenant GUID
]


def tracked_files():
    out = subprocess.run(["git", "ls-files"], cwd=REPO,
                         capture_output=True, text=True).stdout
    return [f for f in out.split() if f]


class NothingIdentifiesARealAccount(unittest.TestCase):

    def test_no_real_identifier_in_any_tracked_file(self):
        hits = []
        for f in tracked_files():
            try:
                text = (REPO / f).read_text(encoding="utf-8")
            except (UnicodeDecodeError, FileNotFoundError, IsADirectoryError):
                continue
            for n, line in enumerate(text.splitlines(), 1):
                low = line.lower()
                for token in _FORBIDDEN:
                    if token.lower() in low:
                        hits.append(f"{f}:{n}: {token}")
                if _REAL_COMPANY_IDS.search(line):
                    hits.append(f"{f}:{n}: bare real company id")
        self.assertEqual(hits, [], "real identifiers in a public repo:\n" + "\n".join(hits))

    def test_this_file_matches_nothing_it_hunts_for(self):
        own = Path(__file__).read_text(encoding="utf-8")
        for token in _FORBIDDEN:
            self.assertEqual(own.count(token), 0, "join broke: literal present")
        self.assertIsNone(_REAL_COMPANY_IDS.search(own))

    def test_the_id_pattern_leaves_ordinary_numbers_alone(self):
        for ok in ("1440", "13300", "25500", "1234567"):
            self.assertIsNone(_REAL_COMPANY_IDS.search(ok), ok)
        self.assertTrue(_REAL_COMPANY_IDS.search("company " + "3" + "30"))
        self.assertTrue(_REAL_COMPANY_IDS.search("te" + "4" + "40"))

    def test_the_customer_facing_surfaces_are_anonymous(self):
        """The deploy templates and the form are what a customer actually
        opens; they must hold the line even if the sweep above ever loosens."""
        for name in ("azuredeploy.json", "createUiDefinition.json"):
            text = (REPO / "deploy" / name).read_text(encoding="utf-8")
            self.assertIsNone(_REAL_COMPANY_IDS.search(text), name)
            for token in _FORBIDDEN:
                self.assertNotIn(token.lower(), text.lower(), f"{name}: {token}")
