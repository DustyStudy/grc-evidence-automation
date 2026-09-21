"""Regenerate the hash-pinned requirement files CI installs from.

    python scripts/lock.py            # re-resolve only what changed; keep existing pins
    python scripts/lock.py --upgrade  # move every pin to the newest allowed version

CI installs with ``pip install --require-hashes -r requirements/requirements-<name>.txt`` so a
compromised or replaced package on the index cannot change what runs. The files are resolved
for every platform and for Python 3.11 and newer (``--universal``). A CI job re-runs this
script and fails if the committed files differ, so they cannot silently go stale.

Requires ``uv``, pinned in ``requirements/requirements-lock-tools.txt``:

    pip install --require-hashes -r requirements/requirements-lock-tools.txt
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQ = "requirements/requirements-"

# lock name -> uv inputs (files and extras) that make up that lock
LOCKS: dict[str, list[str]] = {
    "runtime": ["pyproject.toml"],
    "dev": ["pyproject.toml", "--extra", "dev"],
    "fuzz": ["pyproject.toml", f"{REQ}fuzz.in"],
    "release-tools": [f"{REQ}release-tools.in"],
    "lock-tools": [f"{REQ}lock-tools.in"],
}


def compile_lock(name: str, inputs: list[str], upgrade: bool) -> None:
    out = f"{REQ}{name}.txt"
    cmd = [
        sys.executable, "-m", "uv", "pip", "compile", *inputs,
        "--universal", "--generate-hashes", "--no-header", "--quiet",
        "--python-version", "3.11", "--output-file", out,
    ]  # fmt: skip
    if upgrade:
        cmd.append("--upgrade")
    subprocess.run(cmd, cwd=ROOT, check=True)  # noqa: S603 - fixed argument list, no shell
    print(f"wrote {out}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--upgrade", action="store_true", help="upgrade every pin")
    parser.add_argument(
        "names", nargs="*", metavar="NAME", help=f"locks to regenerate ({', '.join(LOCKS)})"
    )
    args = parser.parse_args()
    unknown = [n for n in args.names if n not in LOCKS]
    if unknown:
        parser.error(f"unknown lock(s): {unknown}")
    for name in args.names or LOCKS:
        compile_lock(name, LOCKS[name], args.upgrade)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
