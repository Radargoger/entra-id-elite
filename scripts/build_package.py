#!/usr/bin/env python3
"""Build the FunctionApp.zip that a release publishes.

Run this instead of `zip -r`. Archives produced by the macOS zip tool mark some
entries 0600, and the Linux worker that unpacks them cannot read those files.
The host still reports Running with no error; it simply indexes zero functions.
Diagnosing that from the outside took three deploys, so the permission bits are
set here explicitly and verified before the file is written.

    python3 scripts/build_package.py --out dist/FunctionApp.zip

Dependencies are taken from an existing package when one is passed with
--deps-from, because .python_packages holds Linux wheels that cannot be built
on a Mac.
"""

import argparse
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "FunctionApp"

# Everything the app needs at runtime. Tests and caches stay out of the package.
INCLUDE_SUFFIX = {".py"}
INCLUDE_NAME = {"host.json", "requirements.txt"}
EXCLUDE_PARTS = {"tests", "__pycache__", ".pytest_cache", ".venv"}

FILE_MODE = 0o100644
DIR_MODE = 0o40755


def sources():
    """Every file that belongs in the package, as (arcname, bytes)."""
    for path in sorted(SRC.rglob("*")):
        if path.is_dir():
            continue
        rel = path.relative_to(SRC)
        if EXCLUDE_PARTS & set(rel.parts):
            continue
        if path.suffix in INCLUDE_SUFFIX or path.name in INCLUDE_NAME:
            yield rel.as_posix(), path.read_bytes()


def entry(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0))
    info.create_system = 3  # unix, so external_attr is read as a mode
    info.external_attr = DIR_MODE << 16 | 0x10 if name.endswith("/") else FILE_MODE << 16
    info.compress_type = zipfile.ZIP_DEFLATED
    return info


def verify(path: Path) -> list:
    """Return the entries the Linux worker would fail to read."""
    with zipfile.ZipFile(path) as z:
        if z.testzip() is not None:
            return [f"corrupt: {z.testzip()}"]
        return [i.filename for i in z.infolist()
                if not i.filename.endswith("/") and not (i.external_attr >> 16) & 0o044]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="dist/FunctionApp.zip")
    ap.add_argument("--deps-from", metavar="ZIP",
                    help="existing package to copy .python_packages from "
                         "(Linux wheels cannot be built on macOS)")
    args = ap.parse_args()

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)

    own = dict(sources())
    if not own:
        print("no sources found — wrong directory?", file=sys.stderr)
        return 1

    if args.deps_from:
        # The wheels being reused were resolved against that package's
        # requirements. If ours have moved on, the new dependency is simply
        # absent and the app fails to import it at runtime -- while the host
        # still reports healthy, as ever.
        with zipfile.ZipFile(args.deps_from) as src:
            theirs = src.read("requirements.txt")
        if theirs != (SRC / "requirements.txt").read_bytes():
            print(f"REFUSING: requirements.txt differs from {args.deps_from}. "
                  "Rebuild .python_packages on Linux instead of reusing these.",
                  file=sys.stderr)
            return 1

    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        # Directory entries are optional in the format, but the package proven
        # to deploy carries them. Match it rather than assume the extractor
        # fills them in.
        for d in sorted({f"{Path(n).parent.as_posix()}/" for n in own
                         if Path(n).parent.as_posix() != "."}):
            z.writestr(entry(d), b"")
        for name, data in own.items():
            z.writestr(entry(name), data)

        deps = 0
        if args.deps_from:
            with zipfile.ZipFile(args.deps_from) as src:
                for info in src.infolist():
                    if not info.filename.startswith(".python_packages/"):
                        continue
                    is_dir = info.filename.endswith("/")
                    keep_x = bool((info.external_attr >> 16) & 0o111)
                    new = entry(info.filename)
                    # Directories carry the executable bit as a matter of
                    # course. Restamping them 0o100755 said "regular file" about
                    # a directory, and verify() below only looks at readability,
                    # so nothing here would have noticed.
                    if keep_x and not is_dir:
                        new.external_attr = 0o100755 << 16
                    z.writestr(new, src.read(info.filename))
                    deps += 1

    unreadable = verify(out)
    if unreadable:
        print(f"REFUSING: {len(unreadable)} entries the Linux worker cannot read",
              file=sys.stderr)
        for name in unreadable[:10]:
            print(f"  {name}", file=sys.stderr)
        out.unlink()
        return 1

    print(f"{out}  ({out.stat().st_size} bytes)")
    print(f"  {len(own)} source files, {deps} dependency files")
    if not deps:
        print("  WARNING: no .python_packages — pass --deps-from or the app "
              "will fail to import azure.* at runtime", file=sys.stderr)
    print("  every entry is world-readable")
    return 0


if __name__ == "__main__":
    sys.exit(main())
