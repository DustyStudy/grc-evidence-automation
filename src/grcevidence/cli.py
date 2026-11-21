"""``grc-evidence`` command line interface."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

from botocore.exceptions import BotoCoreError, ClientError

from grcevidence import __version__
from grcevidence.catalog import (
    FRAMEWORKS,
    collectors_markdown,
    coverage,
    coverage_markdown,
    validate_mapping,
)
from grcevidence.collectors.base import load_all
from grcevidence.report import load_run, report_markdown, rollup, verify_run
from grcevidence.runner import Config, ConfigError, aws_session, build_sinks, deliver, run
from grcevidence.sinks import SinkError


def cmd_collectors(args: argparse.Namespace) -> int:
    collectors = load_all()
    if args.format == "markdown":
        print(collectors_markdown())
        return 0
    for cid, cls in collectors.items():
        print(f"{cid:<28} {cls.scope:<8} {cls.title}")
    return 0


def cmd_coverage(args: argparse.Namespace) -> int:
    if args.check:
        problems = validate_mapping(list(load_all()))
        for p in problems:
            print(f"mapping problem: {p}", file=sys.stderr)
        print("mapping OK" if not problems else f"{len(problems)} mapping problem(s)")
        return 1 if problems else 0
    if args.format == "markdown":
        print(coverage_markdown())
        return 0
    for fw in [args.framework] if args.framework else FRAMEWORKS:
        rows = coverage(fw)
        tech = [r for r in rows if r.type == "technical"]
        auto = [r for r in tech if r.automated]
        print(f"{fw}: {len(auto)}/{len(tech)} technical controls have automated evidence")
        for r in tech:
            if not r.automated:
                print(f"   gap: {r.control}  {r.title}")
    return 0


def cmd_permissions(_: argparse.Namespace) -> int:
    actions = sorted(
        {a for c in load_all().values() if c.provider == "aws" for a in c.permissions}
        | {"sts:GetCallerIdentity"}
    )
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "GrcEvidenceReadOnly", "Effect": "Allow", "Action": actions, "Resource": "*"}
        ],
    }
    print(json.dumps(policy, indent=2))
    return 0


def cmd_collect(args: argparse.Namespace) -> int:
    try:
        config = Config.from_file(args.config) if args.config else Config()
        if args.only:
            config.include = args.only.split(",")
        if args.regions:
            config.regions = args.regions.split(",")
        if args.output:
            config.sinks = [{"type": "local", "path": args.output}]
        session = aws_session(config.use_fips_endpoint)
        sinks = [] if args.dry_run else build_sinks(config.sinks, session=session)
        if not sinks and not args.dry_run:
            print(
                "error: no sinks configured; pass --output DIR or add sinks to the config (or use --dry-run)",
                file=sys.stderr,
            )
            return 2
        result = deliver(run(config, session=session, sinks=sinks), sinks)
    except (ConfigError, ValueError, OSError, SinkError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    counts = ", ".join(f"{k}={v}" for k, v in sorted(result.manifest.counts.items()))
    print(f"run {result.manifest.run_id}: {len(result.evidence)} evidence record(s) ({counts})")
    for ev in result.evidence:
        mark = {
            "pass": "PASS",
            "fail": "FAIL",
            "error": "ERR ",
            "info": "INFO",
            "not_applicable": "N/A ",
        }[ev.status.value]
        print(f"  [{mark}] {ev.id}: {ev.summary}")
    for name, outcome in result.sink_results.items():
        print(f"  sink {name}: {outcome}")
    if result.failed_sinks:
        return 3
    if args.fail_on_findings and any(e.status.value in {"fail", "error"} for e in result.evidence):
        return 1
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    try:
        manifest, evidence = load_run(args.input)
    except (OSError, KeyError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.format == "json":
        print(json.dumps([r.__dict__ for r in rollup(evidence, args.framework)], indent=2))
    else:
        print(report_markdown(manifest, evidence, args.framework))
    return 0


def _download_s3(url: str, dest: Path) -> None:
    """Copy every object under s3://bucket/prefix to the same relative path under ``dest``."""
    bucket, _, prefix = url.removeprefix("s3://").partition("/")
    if prefix and not prefix.endswith("/"):
        prefix += "/"
    s3 = aws_session().client("s3")
    root = dest.resolve()
    seen: set[str] = set()
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            if key.endswith("/"):
                continue  # folder marker
            parts = key.split("/")
            target = dest.joinpath(*parts)
            # Keys are untrusted: none may land outside the temporary directory or overwrite
            # another key's file (case-insensitive filesystems, empty or "." segments).
            if (
                any(p in {"", ".", ".."} for p in parts)
                or root not in target.resolve().parents
                or str(target).casefold() in seen
            ):
                raise ValueError(f"refusing unsafe or colliding S3 key {key!r}")
            seen.add(str(target).casefold())
            target.parent.mkdir(parents=True, exist_ok=True)
            s3.download_file(bucket, key, str(target))


def cmd_verify(args: argparse.Namespace) -> int:
    opts = {"key_id": args.key_id, "check_signature": not args.skip_signature}
    try:
        if args.input.startswith("s3://"):
            with tempfile.TemporaryDirectory(prefix="grc-verify-") as tmp:
                _download_s3(args.input, Path(tmp))
                result = verify_run(tmp, **opts)
            result.notes.append("S3: checked the current version of each object only")
        else:
            result = verify_run(args.input, **opts)
    except (OSError, KeyError, ValueError, ClientError, BotoCoreError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    for p in result.problems:
        print(f"TAMPERED/INCONSISTENT: {p}", file=sys.stderr)
    for n in result.notes:
        print(f"NOTE: {n}")
    if result.problems:
        print(f"{len(result.problems)} problem(s)")
        return 1
    checked = ["manifest and evidence hashes"]
    if result.signatures:
        checked.append(f"{result.signatures} signature(s)")
    if result.unsigned:
        checked.append(f"{result.unsigned} unsigned")
    if result.chain_checked:
        checked.append("chain links")
    print(f"OK: {result.runs} run(s) verified ({', '.join(checked)})")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="grc-evidence", description="Cloud control-evidence automation."
    )
    p.add_argument("--version", action="version", version=f"grc-evidence {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    lc = sub.add_parser("collectors", help="List available collectors.")
    lc.add_argument("--format", choices=["text", "markdown"], default="text")
    lc.set_defaults(func=cmd_collectors)

    c = sub.add_parser("coverage", help="Show which controls have automated evidence.")
    c.add_argument("--framework", choices=FRAMEWORKS)
    c.add_argument("--format", choices=["text", "markdown"], default="text")
    c.add_argument(
        "--check", action="store_true", help="validate the crosswalk and exit non-zero on problems"
    )
    c.set_defaults(func=cmd_coverage)

    sub.add_parser(
        "permissions", help="Print the read-only IAM policy the AWS collectors need."
    ).set_defaults(func=cmd_permissions)

    k = sub.add_parser(
        "collect", help="Run collectors and deliver evidence to the configured sinks."
    )
    k.add_argument("--config", help="YAML config file")
    k.add_argument(
        "--output", help="shortcut: write to this local directory (replaces config sinks)"
    )
    k.add_argument("--only", help="comma-separated collector ids")
    k.add_argument("--regions", help="comma-separated regions (overrides config)")
    k.add_argument("--dry-run", action="store_true", help="collect and print, write nothing")
    k.add_argument(
        "--fail-on-findings", action="store_true", help="exit 1 if any evidence is fail/error"
    )
    k.set_defaults(func=cmd_collect)

    r = sub.add_parser("report", help="Roll a stored run up to per-control status.")
    r.add_argument("input", help="run directory, or a parent of run directories (latest is used)")
    r.add_argument("--framework", choices=FRAMEWORKS, default="soc2")
    r.add_argument("--format", choices=["markdown", "json"], default="markdown")
    r.set_defaults(func=cmd_report)

    v = sub.add_parser(
        "verify", help="Verify stored runs: hashes, manifest signatures and the chain of runs."
    )
    v.add_argument(
        "input", help="run directory, parent of run directories, or s3://bucket/prefix (all runs)"
    )
    v.add_argument(
        "--key-id", help="pin the KMS key (ARN) runs must be signed with; unsigned runs then fail"
    )
    v.add_argument(
        "--skip-signature", action="store_true", help="do not call KMS to check signatures"
    )
    v.set_defaults(func=cmd_verify)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
