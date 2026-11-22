"""Regenerate the hash-pinned requirement files CI installs from.

    python scripts/lock.py            # re-resolve only what changed; keep existing pins
    python scripts/lock.py --upgrade  # move every pin to the newest allowed version
    python scripts/lock.py --check    # write nothing; exit 1 if a committed file is stale

CI installs with ``pip install --require-hashes -r requirements/requirements-<name>.txt`` so a
compromised or replaced package on the index cannot change what runs. The files are resolved
for every platform and for Python 3.11 and newer (``--universal``). A CI job runs this
script with ``--check`` and fails if the committed files differ, so they cannot silently go stale.

Requires ``uv``, pinned in ``requirements/requirements-lock-tools.txt``:

    pip install --require-hashes -r requirements/requirements-lock-tools.txt
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQ = "requirements/requirements-"

# lock name -> uv inputs (files and extras) that make up that lock
LOCKS: dict[str, list[str]] = {
    "runtime": ["pyproject.toml"],
    "dev": ["pyproject.toml", "--extra", "dev", f"{REQ}build.in"],
    "fuzz": ["pyproject.toml", f"{REQ}fuzz.in", f"{REQ}build.in"],
    "gcp": ["pyproject.toml", "--extra", "gcp"],
    "lambda": [f"{REQ}lambda.in"],  # what the Lambda zip adds to the runtime's boto3
    "release-tools": [f"{REQ}release-tools.in", f"{REQ}build.in"],
    "lock-tools": [f"{REQ}lock-tools.in"],
}


def compile_lock(name: str, inputs: list[str], upgrade: bool, out: str | None = None) -> None:
    out = out or f"{REQ}{name}.txt"
    cmd = [
        sys.executable, "-m", "uv", "pip", "compile", *inputs,
        "--universal", "--generate-hashes", "--no-header", "--quiet",
        "--python-version", "3.11", "--output-file", out,
    ]  # fmt: skip
    if upgrade:
        cmd.append("--upgrade")
    subprocess.run(cmd, cwd=ROOT, check=True)  # noqa: S603 - fixed argument list, no shell


def check_locks(names: list[str]) -> list[str]:
    """Names of committed lock files that differ from a fresh resolve. Writes nothing in ROOT."""
    drift = []
    with tempfile.TemporaryDirectory() as tmp:
        for name in names:
            committed = ROOT / f"{REQ}{name}.txt"
            fresh = Path(tmp) / committed.name
            if committed.exists():
                shutil.copyfile(committed, fresh)  # uv keeps the pins already in its output file
            compile_lock(name, LOCKS[name], upgrade=False, out=str(fresh))
            # Text mode: a CRLF checkout is not drift.
            if not committed.exists() or committed.read_text() != fresh.read_text():
                drift.append(f"{REQ}{name}.txt")
    return drift


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--upgrade", action="store_true", help="upgrade every pin")
    mode.add_argument(
        "--check", action="store_true", help="write nothing; exit 1 if a committed file is stale"
    )
    parser.add_argument(
        "names", nargs="*", metavar="NAME", help=f"locks to regenerate ({', '.join(LOCKS)})"
    )
    args = parser.parse_args()
    unknown = [n for n in args.names if n not in LOCKS]
    if unknown:
        parser.error(f"unknown lock(s): {unknown}")
    names = args.names or list(LOCKS)
    if args.check:
        drift = check_locks(names)
        for path in drift:
            print(f"stale: {path} (regenerate with python scripts/lock.py)")
        return 1 if drift else 0
    for name in names:
        compile_lock(name, LOCKS[name], args.upgrade)
        print(f"wrote {REQ}{name}.txt")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
