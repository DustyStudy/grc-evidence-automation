#!/usr/bin/env python3
"""Build the Lambda deployment package (dist/grc-evidence-lambda.zip).

Installs this package and its non-runtime dependencies into a staging directory
for the Lambda Linux runtime (manylinux wheels, so it works from Windows/macOS
too), then zips it. ``boto3`` and ``botocore`` are already in the Lambda Python
runtime, so they are left out to keep the package small.

Third-party code comes only from the hash-pinned ``requirements/requirements-lambda.txt``.
The package is built without build isolation, so install a lock that provides the build
backend first (``requirements-dev.txt`` or ``requirements-release-tools.txt``). The zip is
reproducible: sorted entries, fixed timestamps and permissions.

    python scripts/build_lambda.py [--python-version 3.12] [--arch x86_64|aarch64]
"""

from __future__ import annotations

import argparse
import shutil
import subprocess  # noqa: S404
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "requirements" / "requirements-lambda.txt"


def write_zip(stage: Path, out: Path) -> None:
    """Zip ``stage`` so the same files always give the same bytes."""
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(stage.rglob("*"), key=lambda p: p.relative_to(stage).as_posix()):
            rel = path.relative_to(stage)
            skip = "__pycache__" in rel.parts or rel.parts[0] == "bin"
            skip = skip or any(part.endswith(".dist-info") for part in rel.parts)
            if path.is_file() and not skip:
                info = zipfile.ZipInfo(rel.as_posix(), date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.create_system = 3  # Unix on every build host, so the mode below applies
                info.external_attr = 0o644 << 16
                zf.writestr(info, path.read_bytes())


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--python-version", default="3.12")
    ap.add_argument("--arch", choices=["x86_64", "aarch64"], default="x86_64")
    ap.add_argument("--output", default=str(ROOT / "dist" / "grc-evidence-lambda.zip"))
    args = ap.parse_args()

    platform = "manylinux2014_" + args.arch
    stage = ROOT / "build" / "lambda"
    if stage.exists():
        shutil.rmtree(stage)
    stage.mkdir(parents=True)

    common = [sys.executable, "-m", "pip", "install", "--quiet", "--target", str(stage)]
    # Third-party dependency the runtime lacks (PyYAML), as a Linux wheel from the lock.
    subprocess.run(  # noqa: S603
        [
            *common,
            "--platform",
            platform,
            "--python-version",
            args.python_version,
            "--only-binary=:all:",
            "--implementation",
            "cp",
            "--require-hashes",
            "--no-deps",
            "-r",
            str(LOCK),
        ],
        check=True,
    )
    # This package itself (pure Python), without dependencies, built with the already
    # installed (hash-locked) setuptools rather than one downloaded into an isolated env.
    subprocess.run(  # noqa: S603
        [*common, "--no-deps", "--no-build-isolation", str(ROOT)], check=True
    )

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    write_zip(stage, out)
    print(f"wrote {out} ({out.stat().st_size / 1024:.0f} KiB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
