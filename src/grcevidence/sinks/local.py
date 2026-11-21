"""Filesystem sink: one directory per run, one JSON file per evidence record, plus a manifest."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from grcevidence.models import RunResult
from grcevidence.sinks.base import SinkError, chain_candidate


class LocalSink:
    def __init__(self, path: str | Path) -> None:
        self.root = Path(path)
        self.name = f"local:{self.root}"

    def write(self, run: RunResult) -> int:
        run_dir = self.root / run.manifest.run_id
        try:
            run_dir.mkdir(parents=True, exist_ok=False)
            for ev in run.evidence:
                (run_dir / ev.filename).write_text(
                    json.dumps(ev.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
                )
            # Manifest last: its presence marks the run as complete.
            (run_dir / "manifest.json").write_text(
                json.dumps(run.manifest.to_dict(), indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        except OSError as exc:
            raise SinkError(f"local write failed: {exc}") from exc
        return len(run.evidence) + 1

    def latest_manifest(self, before: str) -> dict[str, Any] | None:
        """Newest well-formed run manifest whose run id sorts before ``before``, else None."""
        try:
            if not self.root.exists():
                return None
            runs = sorted(
                (p for p in self.root.iterdir() if p.name < before),
                key=lambda p: p.name,
                reverse=True,
            )
            for run_dir in runs:
                if (run_dir / "manifest.json").is_file():
                    doc = chain_candidate((run_dir / "manifest.json").read_bytes(), run_dir.name)
                    if doc is not None:
                        return doc
        except OSError as exc:
            raise SinkError(
                f"could not read the latest run manifest under {self.root}: {exc}"
            ) from exc
        return None
