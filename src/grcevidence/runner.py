"""Configuration and orchestration: assume roles, run collectors, seal and deliver evidence."""

from __future__ import annotations

import json
import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from botocore.exceptions import BotoCoreError, ClientError

from grcevidence import __version__
from grcevidence.collectors.base import Collector, Context, Parameters, select
from grcevidence.models import (
    Evidence,
    Finding,
    RunManifest,
    RunResult,
    Severity,
    Status,
    utc_iso,
)
from grcevidence.sinks import HttpSink, LocalSink, S3Sink, Sink, SinkError


class ConfigError(ValueError):
    pass


@dataclass
class AccountConfig:
    id: str | None = None  # 12-digit account id; if omitted, the caller's own account is used
    name: str = ""
    role_arn: str | None = None
    external_id: str | None = None
    regions: list[str] | None = None


@dataclass
class Config:
    accounts: list[AccountConfig] = field(default_factory=list)
    regions: list[str] = field(default_factory=lambda: ["us-east-1"])
    include: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    parameters: Parameters = field(default_factory=Parameters)
    gcp_projects: list[str] = field(default_factory=list)
    sinks: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Config:
        if not isinstance(raw, dict):
            raise ConfigError("config must be a mapping")
        allowed = {"accounts", "regions", "collectors", "parameters", "gcp", "sinks"}
        if unknown := set(raw) - allowed:
            raise ConfigError(f"unknown config key(s): {sorted(unknown)}")
        collectors = raw.get("collectors") or {}
        if unknown := set(collectors) - {"include", "exclude"}:
            raise ConfigError(f"unknown collectors key(s): {sorted(unknown)}")
        accounts = []
        for a in raw.get("accounts") or []:
            if unknown := set(a) - set(AccountConfig.__dataclass_fields__):
                raise ConfigError(f"unknown account key(s): {sorted(unknown)}")
            accounts.append(AccountConfig(**a))
        try:
            params = Parameters.from_dict(raw.get("parameters"))
        except ValueError as exc:
            raise ConfigError(str(exc)) from exc
        return cls(
            accounts=accounts,
            regions=list(raw.get("regions") or ["us-east-1"]),
            include=list(collectors.get("include") or []),
            exclude=list(collectors.get("exclude") or []),
            parameters=params,
            gcp_projects=list((raw.get("gcp") or {}).get("projects") or []),
            sinks=list(raw.get("sinks") or []),
        )

    @classmethod
    def from_file(cls, path: str | Path) -> Config:
        text = Path(path).read_text(encoding="utf-8")
        return cls.from_dict(yaml.safe_load(text) or {})

    @classmethod
    def from_json(cls, text: str) -> Config:
        return cls.from_dict(json.loads(text))


def build_sinks(specs: list[dict[str, Any]], session: Any = None) -> list[Sink]:
    sinks: list[Sink] = []
    for spec in specs:
        spec = dict(spec)
        kind = spec.pop("type", None)
        try:
            if kind == "local":
                sinks.append(LocalSink(spec.pop("path")))
            elif kind == "s3":
                sinks.append(S3Sink(spec.pop("bucket"), session=session, **spec))
            elif kind == "http":
                sinks.append(HttpSink(spec.pop("url"), session=session, **spec))
            else:
                raise ConfigError(f"unknown sink type {kind!r}; use local, s3 or http")
        except (KeyError, TypeError) as exc:
            raise ConfigError(f"invalid {kind} sink config: {exc}") from exc
        except SinkError as exc:
            raise ConfigError(str(exc)) from exc
    return sinks


# ------------------------------------------------------------------------ execution
def _assume(base: Any, acct: AccountConfig) -> Any:
    import boto3

    kwargs: dict[str, Any] = {
        "RoleArn": acct.role_arn,
        "RoleSessionName": "grc-evidence",
        "DurationSeconds": 3600,
    }
    if acct.external_id:
        kwargs["ExternalId"] = acct.external_id
    creds = base.client("sts").assume_role(**kwargs)["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )


def _access_error(account: str, exc: Exception, now: datetime) -> Evidence:
    detail = f"{type(exc).__name__}: {exc}"
    return Evidence(
        collector="aws.account_access",
        provider="aws",
        title="Access to account for evidence collection",
        account=account,
        region="global",
        collected_at=utc_iso(now),
        status=Status.ERROR,
        summary="Could not obtain credentials for this account; no evidence was collected",
        findings=[Finding(account, detail[:300], Severity.HIGH)],
    ).seal()


def run(
    config: Config,
    *,
    session: Any = None,
    now: datetime | None = None,
    collectors: list[type[Collector]] | None = None,
    gcp_clients: Any = None,
) -> RunResult:
    """Run every selected collector across accounts/regions and return sealed evidence."""
    import boto3

    started = now or datetime.now(UTC)
    base = session or boto3.Session()
    chosen = collectors if collectors is not None else select(config.include, config.exclude)
    aws = [c for c in chosen if c.provider == "aws"]
    gcp = [c for c in chosen if c.provider == "gcp"]

    evidence: list[Evidence] = []
    accounts_seen: list[str] = []

    if aws:
        for acct in config.accounts or [AccountConfig()]:
            label = acct.id or acct.role_arn or "current"
            try:
                sess = _assume(base, acct) if acct.role_arn else base
                account_id = sess.client("sts").get_caller_identity()["Account"]
                if acct.id and acct.id != account_id:
                    raise ConfigError(
                        f"configured account {acct.id} but credentials are for {account_id}"
                    )
            except (ClientError, BotoCoreError, ConfigError) as exc:
                evidence.append(_access_error(label, exc, started))
                accounts_seen.append(label)
                continue
            accounts_seen.append(account_id)
            regions = acct.regions or config.regions
            for cls in aws:
                targets = regions[:1] if cls.scope == "global" else regions
                for region in targets:
                    ctx = Context(account_id, region, sess, config.parameters, started)
                    evidence.append(cls().execute(ctx))

    for project in config.gcp_projects:
        accounts_seen.append(f"gcp:{project}")
        for cls in gcp:
            ctx = Context(project, "global", None, config.parameters, started, project, gcp_clients)
            evidence.append(cls().execute(ctx))

    finished = datetime.now(UTC) if now is None else started
    run_id = f"{started.strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"
    manifest = RunManifest(
        run_id=run_id,
        started_at=utc_iso(started),
        finished_at=utc_iso(finished),
        tool_version=__version__,
        accounts=sorted(set(accounts_seen)),
        counts=dict(Counter(e.status.value for e in evidence)),
        evidence=[
            {"id": e.id, "file": e.filename, "status": e.status.value, "sha256": e.sha256}
            for e in evidence
        ],
    ).seal()
    return RunResult(manifest=manifest, evidence=evidence)


def deliver(result: RunResult, sinks: list[Sink]) -> RunResult:
    """Write to every sink; one sink failing does not prevent the others."""
    for sink in sinks:
        try:
            sink.write(result)
            result.sink_results[sink.name] = "ok"
        except (SinkError, ValueError) as exc:
            result.sink_results[sink.name] = f"failed: {exc}"
    return result
