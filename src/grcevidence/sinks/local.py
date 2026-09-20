"""Filesystem sink: one directory per run, one JSON file per evidence record, plus a manifest."""

from __future__ import annotations

import json
from pathlib import Path

from grcevidence.models import RunResult
from grcevidence.sinks.base import SinkError


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
