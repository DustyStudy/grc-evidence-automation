"""Load stored evidence, verify integrity, and roll findings up to control status."""

from __future__ import annotations

import json
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path

from grcevidence.catalog import FRAMEWORK_LABELS, FRAMEWORKS, controls
from grcevidence.models import Evidence, RunManifest, Status

NO_EVIDENCE = "no_automated_evidence"


def latest_run_dir(path: Path) -> Path:
    """Accept a run directory itself or a parent containing run directories."""
    if (path / "manifest.json").exists():
        return path
    runs = sorted(p for p in path.iterdir() if p.is_dir() and (p / "manifest.json").exists())
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


def verify_run(path: str | Path) -> list[str]:
    """Check every stored record against its own hash and the manifest. Empty list = intact."""
    run_dir = latest_run_dir(Path(path))
    problems: list[str] = []
    try:
        manifest = _read_manifest(run_dir)
    except ValueError as exc:
        # Tampered or damaged content is a finding to report, not a reason to crash.
        return [str(exc)]
    if not manifest.verify():
        problems.append("manifest hash does not match its contents")
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


@dataclass
class ControlStatus:
    control: str
    title: str
    status: str
    evidence: list[str] = field(default_factory=list)
    failing: list[str] = field(default_factory=list)


def rollup(evidence: list[Evidence], framework: str) -> list[ControlStatus]:
    """Status per control: fail > error > pass > not_applicable; none -> no_automated_evidence."""
    if framework not in FRAMEWORKS:
        raise ValueError(f"unknown framework {framework!r}; choose from {list(FRAMEWORKS)}")
    by_control: dict[str, list[Evidence]] = {}
    for ev in evidence:
        for cid in ev.controls.get(framework, []):
            by_control.setdefault(cid, []).append(ev)
    rows: list[ControlStatus] = []
    for cid, meta in controls()[framework].items():
        evs = by_control.get(cid, [])
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
