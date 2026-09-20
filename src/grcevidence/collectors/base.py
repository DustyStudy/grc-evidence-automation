"""Collector base class, execution context and registry."""

from __future__ import annotations

import importlib
import pkgutil
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, ClassVar

from botocore.config import Config as BotoConfig
from botocore.exceptions import BotoCoreError, ClientError

from grcevidence.catalog import controls_for
from grcevidence.models import Evidence, Finding, Severity, Status, utc_iso

_BOTO_CONFIG = BotoConfig(
    retries={"max_attempts": 8, "mode": "adaptive"}, user_agent_extra="grc-evidence"
)


@dataclass
class Parameters:
    """Tunable thresholds. Defaults follow common benchmark guidance (e.g. CIS AWS Foundations)
    but your own policy, not these defaults, is what an auditor tests against."""

    max_access_key_age_days: int = 90
    max_access_key_unused_days: int = 45
    password_min_length: int = 14
    password_reuse_prevention: int = 24
    sensitive_ports: tuple[int, ...] = (22, 3389)
    min_backup_retention_days: int = 7
    require_securityhub: bool = False
    max_items_per_check: int = 500  # cap on resources examined per collector per region

    @classmethod
    def from_dict(cls, raw: dict[str, Any] | None) -> Parameters:
        raw = dict(raw or {})
        known = set(cls.__dataclass_fields__)
        unknown = set(raw) - known
        if unknown:
            raise ValueError(f"unknown parameter(s): {sorted(unknown)}; known: {sorted(known)}")
        if "sensitive_ports" in raw:
            raw["sensitive_ports"] = tuple(int(p) for p in raw["sensitive_ports"])
        return cls(**raw)


@dataclass
class Context:
    account: str
    region: str
    session: Any = None  # boto3.Session for AWS collectors
    params: Parameters = field(default_factory=Parameters)
    now: datetime = field(default_factory=lambda: datetime.now(UTC))
    gcp_project: str | None = None
    gcp_clients: Any = None  # object exposing .storage() and .firewalls(); injectable for tests

    @property
    def partition(self) -> str:
        """AWS partition for building ARNs (commercial, GovCloud, China)."""
        if self.region.startswith("us-gov-"):
            return "aws-us-gov"
        if self.region.startswith("cn-"):
            return "aws-cn"
        return "aws"

    def client(self, service: str, region: str | None = None) -> Any:
        return self.session.client(service, region_name=region or self.region, config=_BOTO_CONFIG)


@dataclass
class Result:
    """What a collector's ``collect`` returns; the base class turns it into :class:`Evidence`."""

    summary: str
    findings: list[Finding] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)
    status: Status | None = None  # override; default is PASS/FAIL from findings


class Collector:
    id: ClassVar[str]
    provider: ClassVar[str] = "aws"
    title: ClassVar[str]
    scope: ClassVar[str] = "regional"  # "global" collectors run once per account
    permissions: ClassVar[
        tuple[str, ...]
    ] = ()  # IAM actions needed; drives docs and IAM policy checks

    def collect(self, ctx: Context) -> Result:  # pragma: no cover - interface
        raise NotImplementedError

    def _evidence(
        self,
        ctx: Context,
        status: Status,
        summary: str,
        findings: list[Finding],
        data: dict[str, Any] | None = None,
    ) -> Evidence:
        return Evidence(
            collector=self.id,
            provider=self.provider,
            title=self.title,
            account=ctx.account,
            region="global" if self.scope == "global" else ctx.region,
            collected_at=utc_iso(ctx.now),
            status=status,
            summary=summary,
            findings=findings,
            data=data or {},
            controls=controls_for(self.id),
        ).seal()

    def execute(self, ctx: Context) -> Evidence:
        """Run ``collect`` and always return sealed evidence, even on failure.

        An inability to check (denied, throttled, service down) is recorded as
        ``ERROR``, never silently treated as a pass.
        """
        try:
            result = self.collect(ctx)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            code = err.get("Code", "ClientError")
            finding = Finding(self.id, f"{code}: {err.get('Message', '')}", Severity.LOW)
            return self._evidence(ctx, Status.ERROR, f"Could not collect: {code}", [finding])
        except (BotoCoreError, OSError, ValueError, KeyError, AttributeError, ImportError) as exc:
            finding = Finding(self.id, f"{type(exc).__name__}: {exc}", Severity.LOW)
            return self._evidence(
                ctx, Status.ERROR, f"Could not collect: {type(exc).__name__}", [finding]
            )
        status = result.status or (Status.FAIL if result.findings else Status.PASS)
        return self._evidence(ctx, status, result.summary, result.findings, result.data)


# ---------------------------------------------------------------------- registry
REGISTRY: dict[str, type[Collector]] = {}


def register(cls: type[Collector]) -> type[Collector]:
    if cls.id in REGISTRY and REGISTRY[cls.id] is not cls:
        raise ValueError(f"duplicate collector id {cls.id!r}")
    REGISTRY[cls.id] = cls
    return cls


def load_all() -> dict[str, type[Collector]]:
    """Import every collector module so they register themselves."""
    from grcevidence import collectors

    for mod in pkgutil.walk_packages(collectors.__path__, collectors.__name__ + "."):
        if not mod.name.endswith(".base"):
            importlib.import_module(mod.name)
    return dict(sorted(REGISTRY.items()))


def select(
    include: list[str] | None = None,
    exclude: list[str] | None = None,
    provider: str | None = None,
) -> list[type[Collector]]:
    everything = load_all()
    for name in [*(include or []), *(exclude or [])]:
        if name not in everything:
            raise ValueError(f"unknown collector {name!r}; see `grc-evidence collectors`")
    chosen = [
        c
        for cid, c in everything.items()
        if (not include or cid in include)
        and cid not in (exclude or [])
        and (provider is None or c.provider == provider)
    ]
    return chosen


def paginate(client: Any, op: str, key: str, limit: int | None = None, **kwargs: Any) -> list[Any]:
    """Collect items from a paginated boto3 call, capped at ``limit``."""
    items: list[Any] = []
    for page in client.get_paginator(op).paginate(**kwargs):
        items.extend(page.get(key, []))
        if limit is not None and len(items) >= limit:
            return items[:limit]
    return items


Check = Callable[[Context], Result]
