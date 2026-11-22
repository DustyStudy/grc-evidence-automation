"""Load stored evidence, verify integrity, and roll findings up to control status."""

from __future__ import annotations

import base64
import json
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from grcevidence.catalog import FRAMEWORK_LABELS, FRAMEWORKS, controls
from grcevidence.models import SCHEMA_VERSION, Evidence, RunManifest, Status, kms_region

NO_EVIDENCE = "no_automated_evidence"


def run_dirs(path: Path) -> list[Path]:
    """``[path]`` for a run directory, else every run directory below it, oldest first.

    Recursive, so an ``aws s3 sync`` copy with ``dt=`` partitions works; run ids start with a
    UTC timestamp, so sorting by directory name is chronological.
    """
    if (path / "manifest.json").exists():
        return [path]
    return sorted(
        (m.parent for m in path.rglob("manifest.json") if m.is_file()), key=lambda p: p.name
    )


def latest_run_dir(path: Path) -> Path:
    """Accept a run directory itself or a parent containing run directories."""
    runs = run_dirs(path)
    if not runs:
        raise FileNotFoundError(f"no completed run (manifest.json) found under {path}")
    return runs[-1]


def _is_plain_filename(name: object) -> bool:
    """A manifest may only name files directly inside its own run directory.

    The manifest is data read from disk. Without this check ``"file": "../../x.json"`` or an
    absolute path would make the verifier and the report read (and vouch for) files outside the
    run directory.
    """
    return (
        isinstance(name, str)
        and name not in {"", ".", "..", "manifest.json"}
        and Path(name).name == name
        and "\\" not in name
        and name.endswith(".json")
    )


def _read_manifest(run_dir: Path) -> RunManifest:
    """Load the manifest, turning any malformed content into ValueError."""
    try:
        return RunManifest.from_dict(
            json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
        )
    except (KeyError, TypeError, AttributeError, ValueError) as exc:
        raise ValueError(
            f"manifest.json is unreadable or malformed ({type(exc).__name__})"
        ) from exc


def _read_evidence(path: Path) -> Evidence:
    """Load one evidence file, turning any malformed content into ValueError."""
    try:
        return Evidence.from_dict(json.loads(path.read_text(encoding="utf-8")))
    except (KeyError, TypeError, AttributeError, ValueError) as exc:
        raise ValueError(f"{path.name} is unreadable or malformed ({type(exc).__name__})") from exc


def load_run(path: str | Path) -> tuple[RunManifest, list[Evidence]]:
    run_dir = latest_run_dir(Path(path))
    manifest = _read_manifest(run_dir)
    evidence = []
    for item in manifest.evidence:
        name = item.get("file") if isinstance(item, dict) else None
        if not _is_plain_filename(name):
            raise ValueError(f"manifest lists an unsafe evidence file name: {name!r}")
        evidence.append(_read_evidence(run_dir / str(name)))
    return manifest, evidence


@dataclass
class VerifyResult:
    problems: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    runs: int = 0
    signatures: int = 0  # signatures checked and valid
    unsigned: int = 0  # schema 2.0 runs without a signature
    chain_checked: bool = False

    def __bool__(self) -> bool:
        """True when nothing was found wrong."""
        return not self.problems


KmsFactory = Callable[[str], Any]


def _default_kms() -> KmsFactory:
    """KMS clients from the FIPS-aware session, one per region, created only when needed."""
    clients: dict[str | None, Any] = {}

    def get(key_id: str) -> Any:
        from grcevidence import runner  # boto3 only once a signed manifest is actually checked

        region = kms_region(key_id)
        if region not in clients:
            clients[region] = runner.aws_session().client("kms", region_name=region)
        return clients[region]

    return get


def _check_files(run_dir: Path, manifest: RunManifest) -> list[str]:
    """Every stored record against its own hash and the manifest entry."""
    problems: list[str] = []
    listed = {}
    for item in manifest.evidence:
        name = item.get("file") if isinstance(item, dict) else None
        if not _is_plain_filename(name):
            problems.append(f"manifest lists an unsafe evidence file name: {name!r}")
            continue
        listed[str(name)] = item
    on_disk = {p.name for p in run_dir.glob("*.json")} - {"manifest.json"}
    for extra in sorted(on_disk - set(listed)):
        problems.append(f"{extra}: present on disk but not in manifest")
    for name, item in listed.items():
        f = run_dir / name
        if not f.exists():
            problems.append(f"{name}: listed in manifest but missing")
            continue
        try:
            ev = _read_evidence(f)
        except ValueError as exc:
            problems.append(str(exc))
            continue
        if not ev.verify():
            problems.append(f"{name}: content does not match its sha256")
        elif ev.sha256 != item.get("sha256"):
            problems.append(f"{name}: sha256 differs from the manifest entry")
    return problems


def _check_signature(
    m: RunManifest, kms: KmsFactory, key_id: str | None, result: VerifyResult, tag: str
) -> None:
    sig = m.signature
    if sig is None:
        if key_id:
            result.problems.append(f"{tag}unsigned but a signing key was required")
        else:
            result.notes.append(f"{tag}unsigned")
        return
    try:
        value = base64.b64decode(sig["value"], validate=True)
        signer, algorithm = sig["key_id"], sig["algorithm"]
        if not (isinstance(signer, str) and isinstance(algorithm, str) and value):
            raise ValueError
    except (TypeError, KeyError, ValueError):  # binascii.Error is a ValueError
        result.problems.append(f"{tag}signature is malformed")
        return
    key = key_id or signer
    try:
        resp = kms(key).verify(
            KeyId=key,
            Message=bytes.fromhex(m.sha256),
            MessageType="DIGEST",
            Signature=value,
            SigningAlgorithm=algorithm,
        )
        valid = resp.get("SignatureValid") is True
    except Exception as exc:  # anything left unchecked must not pass as OK
        code = getattr(exc, "response", {}).get("Error", {}).get("Code")
        if code != "KMSInvalidSignatureException":
            result.problems.append(f"{tag}signature could not be checked: {exc}")
            return
        valid = False
    if valid:
        result.signatures += 1
    else:
        result.problems.append(f"{tag}signature INVALID")


def _check_chain(runs: list[tuple[str, RunManifest | None]], result: VerifyResult) -> None:
    """Each v2 run must name the run stored immediately before it, with that run's sha256."""
    ids = {m.run_id for _, m in runs if m is not None and isinstance(m.run_id, str)}
    seen_v2 = seen_signed = False
    for i, (name, m) in enumerate(runs):
        if m is None or not (m.legacy or m.schema_version == SCHEMA_VERSION):
            continue  # unreadable or unknown schema: already reported
        tag = f"{name}: "
        if m.legacy:
            if seen_v2:
                result.problems.append(
                    f"{tag}schema {m.schema_version} run after a schema {SCHEMA_VERSION} run "
                    "(downgraded?)"
                )
            continue
        seen_v2 = True
        if m.signature is not None:
            seen_signed = True
        elif seen_signed:
            result.problems.append(f"{tag}unsigned after signed runs (signature stripped?)")
        prev = m.previous
        before = runs[i - 1][1] if i else None
        if prev is None:
            if i:
                result.problems.append(f"{tag}claims genesis but earlier runs exist")
            continue
        if not (
            isinstance(prev, dict)
            and set(prev) == {"run_id", "sha256"}
            and all(isinstance(v, str) for v in prev.values())
        ):
            result.problems.append(f"{tag}previous-run link is malformed")
            continue
        if before is not None and prev["run_id"] == before.run_id:
            if prev["sha256"] != before.sha256:
                result.problems.append(
                    f"{tag}previous run {prev['run_id']} was rewritten "
                    "(its sha256 differs from the link)"
                )
        elif prev["run_id"] in ids:
            result.problems.append(
                f"{tag}links to {prev['run_id']}, not to the run stored before it "
                "(reordered or forked)"
            )
        elif i == 0:
            result.notes.append(
                f"{tag}previous run {prev['run_id']} is not here "
                "(expired by lifecycle, or outside this directory)"
            )
        elif before is not None:
            result.problems.append(f"{tag}previous run {prev['run_id']} is missing (deleted?)")


def verify_run(
    path: str | Path,
    *,
    kms: KmsFactory | None = None,
    key_id: str | None = None,
    check_signature: bool = True,
) -> VerifyResult:
    """Verify one run directory, or every run below a parent directory and the chain between them.

    ``kms`` maps a key id to a KMS client (default: the FIPS-aware session). ``key_id`` pins the
    expected signing key: unsigned runs then fail, and signatures are checked against that key
    instead of the one the manifest names (which a forger could have chosen).
    """
    path = Path(path)
    dirs = run_dirs(path)
    if not dirs:
        raise FileNotFoundError(f"no completed run (manifest.json) found under {path}")
    single = dirs == [path]
    kms = kms or _default_kms()
    result = VerifyResult(runs=len(dirs))
    runs: list[tuple[str, RunManifest | None]] = []
    for run_dir in dirs:
        tag = "" if single else f"{run_dir.name}: "
        try:
            m = _read_manifest(run_dir)
        except ValueError as exc:
            # Tampered or damaged content is a finding to report, not a reason to crash.
            result.problems.append(f"{tag}{exc}")
            runs.append((run_dir.name, None))
            continue
        runs.append((run_dir.name, m))
        if m.run_id != run_dir.name:
            result.problems.append(f"{tag}directory name does not match run_id {m.run_id!r}")
        current = m.schema_version == SCHEMA_VERSION
        if m.legacy:
            result.notes.append(
                f"{tag}legacy schema {m.schema_version}: no signature or chain fields"
            )
        elif not current:
            result.problems.append(f"{tag}unknown schema_version {m.schema_version!r}")
        intact = m.verify()
        if not intact:
            result.problems.append(f"{tag}manifest hash does not match its contents")
        result.problems.extend(tag + p for p in _check_files(run_dir, m))
        if current and m.signature is None:
            result.unsigned += 1
        # A signature over a hash that does not match the content proves nothing.
        if intact and current:
            if check_signature:
                _check_signature(m, kms, key_id, result, tag)
            else:
                result.notes.append(f"{tag}signature not checked (--skip-signature)")
    if key_id and not any(m is not None and m.schema_version == SCHEMA_VERSION for _, m in runs):
        result.problems.append(
            f"no signed schema {SCHEMA_VERSION} run; a pinned key requires at least one"
        )
    if result.signatures and not key_id:
        result.notes.append(
            "signature checked against the key named in the manifest; "
            "pass --key-id to pin the expected key"
        )
    if single:
        result.notes.append("chain: single run; verify the parent directory to check links")
    else:
        _check_chain(runs, result)
        result.chain_checked = True
    return result


@dataclass
class ControlStatus:
    control: str
    title: str
    status: str
    evidence: list[str] = field(default_factory=list)
    failing: list[str] = field(default_factory=list)


def rollup(evidence: list[Evidence], framework: str) -> list[ControlStatus]:
    """Status per control: fail > error > pass > not_applicable; none -> no_automated_evidence.

    An ``aws.account_access`` error applies to every control.
    """
    if framework not in FRAMEWORKS:
        raise ValueError(f"unknown framework {framework!r}; choose from {list(FRAMEWORKS)}")
    by_control: dict[str, list[Evidence]] = {}
    for ev in evidence:
        for cid in ev.controls.get(framework, []):
            by_control.setdefault(cid, []).append(ev)
    # An account that could not be accessed was checked for nothing, so its error counts against
    # every control: the other accounts' passes must not read as a pass for the whole run.
    blocked = [
        e for e in evidence if e.collector == "aws.account_access" and e.status == Status.ERROR
    ]
    rows: list[ControlStatus] = []
    for cid, meta in controls()[framework].items():
        evs = by_control.get(cid, []) + blocked
        statuses = {e.status for e in evs}
        if not evs:
            status = NO_EVIDENCE
        elif Status.FAIL in statuses:
            status = "fail"
        elif Status.ERROR in statuses:
            status = "error"
        elif Status.PASS in statuses:
            status = "pass"
        else:
            status = "not_applicable"
        rows.append(
            ControlStatus(
                cid,
                meta["title"],
                status,
                evidence=sorted({e.collector for e in evs}),
                failing=sorted(
                    {
                        f"{f.resource}: {f.message}"
                        for e in evs
                        if e.status in {Status.FAIL, Status.ERROR}
                        for f in e.findings
                    }
                )[:10],
            )
        )
    return rows


def _cell(text: str) -> str:
    """Make evidence-derived text safe inside one markdown table cell.

    Resource names and messages come from the assessed environment (or from an evidence
    directory of unknown origin), so they must not be able to end the cell, start a new row
    or inject markup into a report a reviewer will open.
    """
    # Line breaks of every kind (including U+2028/U+2029, which several tools treat as newlines)
    # become spaces, and characters that start markdown links, images or code are escaped.
    text = "".join(" " if unicodedata.category(ch) in {"Cc", "Zl", "Zp"} else ch for ch in text)
    return (
        text.replace("\\", "\\\\")
        .replace("|", "/")
        .replace("[", "\\[")
        .replace("]", "\\]")
        .replace("`", "\\`")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def report_markdown(manifest: RunManifest, evidence: list[Evidence], framework: str) -> str:
    rows = rollup(evidence, framework)
    counts: dict[str, int] = {}
    for r in rows:
        counts[r.status] = counts.get(r.status, 0) + 1
    lines = [
        f"# {FRAMEWORK_LABELS[framework]}: control evidence status",
        "",
        f"Run `{_cell(manifest.run_id)}` ({_cell(manifest.started_at)}), "
        f"accounts: {_cell(', '.join(manifest.accounts)) or 'none'}",
        "",
        "**Read this as a triage view, not an audit conclusion.** Automated evidence shows configuration "
        "state at collection time; control effectiveness is the auditor's judgement. `error` means the "
        "check could not run (for example, missing permissions) and is *not* a pass.",
        "",
        "| Status | Controls |",
        "|---|---:|",
        *[f"| {k} | {counts[k]} |" for k in sorted(counts)],
        "",
        "| Control | Title | Status | Evidence from | Top findings |",
        "|---|---|---|---|---|",
    ]
    for r in rows:
        finds = "<br>".join(_cell(x) for x in r.failing[:3]) or "-"
        lines.append(
            f"| {r.control} | {r.title} | {r.status} | {', '.join(_cell(e) for e in r.evidence) or '-'} | {finds} |"
        )
    return "\n".join(lines) + "\n"
