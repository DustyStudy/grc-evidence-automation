"""Evidence data model.

An :class:`Evidence` record is the unit an auditor can sample: what was checked,
where, when, what the result was, and a hash proving the stored record has not
changed since collection. Records never contain secrets or resource contents,
only configuration facts (booleans, counts, identifiers) and findings.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

SCHEMA_VERSION = "1.0"


class Status(StrEnum):
    PASS = "pass"  # checked, no findings
    FAIL = "fail"  # checked, findings present
    ERROR = "error"  # could not be checked (permissions, API failure): NOT a pass
    INFO = "info"  # informational, not judged against a threshold
    NOT_APPLICABLE = "not_applicable"  # e.g. no RDS instances in the region


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class Finding:
    resource: str
    message: str
    severity: Severity = Severity.MEDIUM


@dataclass
class Evidence:
    collector: str
    provider: str
    title: str
    account: str
    region: str
    collected_at: str
    status: Status
    summary: str
    findings: list[Finding] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)
    controls: dict[str, list[str]] = field(default_factory=dict)
    schema_version: str = SCHEMA_VERSION
    sha256: str = ""

    @property
    def id(self) -> str:
        return f"{self.collector}/{self.account}/{self.region}"

    @property
    def filename(self) -> str:
        return re.sub(r"[^A-Za-z0-9._-]+", "__", self.id) + ".json"

    def content_hash(self) -> str:
        """SHA-256 over everything except the hash itself."""
        body = self.to_dict()
        body.pop("sha256", None)
        return hashlib.sha256(canonical_json(body)).hexdigest()

    def seal(self) -> Evidence:
        self.sha256 = self.content_hash()
        return self

    def verify(self) -> bool:
        return bool(self.sha256) and self.sha256 == self.content_hash()

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        d["findings"] = [
            {"resource": f.resource, "message": f.message, "severity": f.severity.value}
            for f in self.findings
        ]
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Evidence:
        return cls(
            collector=d["collector"],
            provider=d["provider"],
            title=d["title"],
            account=d["account"],
            region=d["region"],
            collected_at=d["collected_at"],
            status=Status(d["status"]),
            summary=d["summary"],
            findings=[
                Finding(f["resource"], f["message"], Severity(f.get("severity", "medium")))
                for f in d.get("findings", [])
            ],
            data=d.get("data", {}),
            controls=d.get("controls", {}),
            schema_version=d.get("schema_version", SCHEMA_VERSION),
            sha256=d.get("sha256", ""),
        )


def canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode()


def utc_iso(dt: datetime) -> str:
    return dt.isoformat(timespec="seconds")


@dataclass
class RunManifest:
    run_id: str
    started_at: str
    finished_at: str
    tool_version: str
    accounts: list[str]
    counts: dict[str, int]
    evidence: list[dict[str, str]]
    schema_version: str = SCHEMA_VERSION
    sha256: str = ""

    def content_hash(self) -> str:
        body = asdict(self)
        body.pop("sha256", None)
        return hashlib.sha256(canonical_json(body)).hexdigest()

    def seal(self) -> RunManifest:
        self.sha256 = self.content_hash()
        return self

    def verify(self) -> bool:
        return bool(self.sha256) and self.sha256 == self.content_hash()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> RunManifest:
        return cls(**d)


@dataclass
class RunResult:
    manifest: RunManifest
    evidence: list[Evidence]
    sink_results: dict[str, str] = field(default_factory=dict)

    @property
    def failed_sinks(self) -> dict[str, str]:
        return {k: v for k, v in self.sink_results.items() if v != "ok"}
