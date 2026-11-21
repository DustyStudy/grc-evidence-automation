"""Sink interface: where finished evidence goes."""

from __future__ import annotations

import json
from typing import Any, Protocol

from grcevidence.models import RunResult


class SinkError(RuntimeError):
    pass


def chain_candidate(raw: bytes, run_dir: str) -> dict[str, Any] | None:
    """A stored manifest usable as the chain head, or None to skip it.

    Malformed or misplaced manifests are skipped rather than raised: under Object Lock a planted
    one can never be removed and would otherwise block collection forever. ``verify`` still
    reports them.
    """
    try:
        doc = json.loads(raw)
    except ValueError:  # includes invalid UTF-8
        return None
    if (
        isinstance(doc, dict)
        and doc.get("run_id") == run_dir
        and isinstance(doc.get("sha256"), str)
    ):
        return doc
    return None


class Sink(Protocol):
    name: str

    def write(self, run: RunResult) -> int:
        """Persist the run. Returns the number of objects/requests written. Raises SinkError."""
        ...
