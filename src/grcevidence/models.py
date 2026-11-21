"""Evidence data model.

An :class:`Evidence` record is the unit an auditor can sample: what was checked,
where, when, what the result was, and a hash proving the stored record has not
changed since collection. Records never contain secrets or resource contents,
only configuration facts (booleans, counts, identifiers) and findings.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

SCHEMA_VERSION = "2.0"
# Stored with the v1 manifest field set; still verifiable, but carry no signature or chain link.
LEGACY_SCHEMA_VERSIONS = {"1.0"}
_V1_MANIFEST_FIELDS = (
    "run_id",
    "started_at",
    "finished_at",
    "tool_version",
    "accounts",
    "counts",
    "evidence",
    "schema_version",
    "sha256",
)
SIGNING_ALGORITHM = "ECDSA_SHA_256"


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
        stem = re.sub(r"[^A-Za-z0-9._-]+", "__", self.id)
        if len(stem) > 180:  # stay well under common 255-byte name limits, and stay unique
            stem = stem[:150] + "-" + hashlib.sha256(self.id.encode()).hexdigest()[:16]
        return stem + ".json"

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
        # Keys of any type become strings exactly as they will after a write/read round trip,
        # so the hash is the same before and after storage and sorting cannot fail on mixed keys.
        d["data"] = _plain(d["data"])
        d["controls"] = _plain(d["controls"])
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


def _plain(value: Any) -> Any:
    """Round-trip through JSON: what a value looks like once written to disk and read back."""
    return json.loads(json.dumps(value, default=str))


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
    collectors: list[str] = field(default_factory=list)  # selected collector ids
    parameters: dict[str, Any] = field(default_factory=dict)  # thresholds judged against
    config_sha256: str = ""  # effective config, which holds secret references, never values
    previous: dict[str, str] | None = None  # {"run_id", "sha256"} of the prior run; None = genesis
    schema_version: str = SCHEMA_VERSION
    sha256: str = ""
    signature: dict[str, str] | None = None  # KMS signature over sha256

    @property
    def legacy(self) -> bool:
        return (
            isinstance(self.schema_version, str) and self.schema_version in LEGACY_SCHEMA_VERSIONS
        )

    def content_hash(self) -> str:
        """SHA-256 over everything except the hash and the signature (which signs the hash)."""
        body = self.to_dict()
        body.pop("sha256", None)
        body.pop("signature", None)
        return hashlib.sha256(canonical_json(body)).hexdigest()

    def seal(self) -> RunManifest:
        self.sha256 = self.content_hash()
        return self

    def verify(self) -> bool:
        return bool(self.sha256) and self.sha256 == self.content_hash()

    def sign(self, kms: Any, key_id: str) -> RunManifest:
        """Sign the sealed hash with an asymmetric KMS key (``kms`` is a boto3 KMS client)."""
        resp = kms.sign(
            KeyId=key_id,
            Message=bytes.fromhex(self.sha256),
            MessageType="DIGEST",
            SigningAlgorithm=SIGNING_ALGORITHM,
        )
        self.signature = {
            "key_id": resp["KeyId"],
            "algorithm": SIGNING_ALGORITHM,
            "value": base64.b64encode(resp["Signature"]).decode(),
        }
        return self

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        # Stored v1 manifests were hashed over exactly these fields; keep them byte-for-byte.
        return {k: d[k] for k in _V1_MANIFEST_FIELDS} if self.legacy else d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> RunManifest:
        return cls(**d)


def kms_region(key_id: str) -> str | None:
    """Region of a KMS key or alias ARN (``arn:<partition>:kms:<region>:...``); None otherwise."""
    parts = key_id.split(":")
    return (parts[3] or None) if key_id.startswith("arn:") and len(parts) > 4 else None


@dataclass
class RunResult:
    manifest: RunManifest
    evidence: list[Evidence]
    sink_results: dict[str, str] = field(default_factory=dict)

    @property
    def failed_sinks(self) -> dict[str, str]:
        return {k: v for k, v in self.sink_results.items() if v != "ok"}
