"""Load stored evidence, verify integrity, and roll findings up to control status."""

from __future__ import annotations

import json
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


def load_run(path: str | Path) -> tuple[RunManifest, list[Evidence]]:
    run_dir = latest_run_dir(Path(path))
    manifest = RunManifest.from_dict(
        json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    )
    evidence = [
        Evidence.from_dict(json.loads((run_dir / item["file"]).read_text(encoding="utf-8")))
        for item in manifest.evidence
    ]
    return manifest, evidence


def verify_run(path: str | Path) -> list[str]:
    """Check every stored record against its own hash and the manifest. Empty list = intact."""
    run_dir = latest_run_dir(Path(path))
    problems: list[str] = []
    manifest = RunManifest.from_dict(
        json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    )
    if not manifest.verify():
        problems.append("manifest hash does not match its contents")
    listed = {item["file"]: item for item in manifest.evidence}
    on_disk = {p.name for p in run_dir.glob("*.json")} - {"manifest.json"}
    for extra in sorted(on_disk - set(listed)):
        problems.append(f"{extra}: present on disk but not in manifest")
    for name, item in listed.items():
        f = run_dir / name
        if not f.exists():
            problems.append(f"{name}: listed in manifest but missing")
            continue
        ev = Evidence.from_dict(json.loads(f.read_text(encoding="utf-8")))
        if not ev.verify():
            problems.append(f"{name}: content does not match its sha256")
        elif ev.sha256 != item["sha256"]:
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


def report_markdown(manifest: RunManifest, evidence: list[Evidence], framework: str) -> str:
    rows = rollup(evidence, framework)
    counts: dict[str, int] = {}
    for r in rows:
        counts[r.status] = counts.get(r.status, 0) + 1
    lines = [
        f"# {FRAMEWORK_LABELS[framework]}: control evidence status",
        "",
        f"Run `{manifest.run_id}` ({manifest.started_at}), accounts: {', '.join(manifest.accounts) or 'none'}",
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
        finds = "<br>".join(x.replace("|", "/") for x in r.failing[:3]) or "-"
        lines.append(
            f"| {r.control} | {r.title} | {r.status} | {', '.join(r.evidence) or '-'} | {finds} |"
        )
    return "\n".join(lines) + "\n"
