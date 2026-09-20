#!/usr/bin/env python3
"""Build the Lambda deployment package (dist/grc-evidence-lambda.zip).

Installs this package and its non-runtime dependencies into a staging directory
for the Lambda Linux runtime (manylinux wheels, so it works from Windows/macOS
too), then zips it. ``boto3`` and ``botocore`` are already in the Lambda Python
runtime, so they are left out to keep the package small.

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
    # Third-party dependency the runtime lacks (PyYAML), as a Linux wheel.
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
            "PyYAML>=6.0",
        ],
        check=True,
    )
    # This package itself (pure Python), without dependencies.
    subprocess.run([*common, "--no-deps", str(ROOT)], check=True)  # noqa: S603

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(stage.rglob("*")):
            rel = path.relative_to(stage)
            skip = "__pycache__" in rel.parts or rel.parts[0] == "bin"
            skip = skip or any(part.endswith(".dist-info") for part in rel.parts)
            if path.is_file() and not skip:
                zf.write(path, rel.as_posix())
    print(f"wrote {out} ({out.stat().st_size / 1024:.0f} KiB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
