"""Sink interface: where finished evidence goes."""

from __future__ import annotations

from typing import Protocol

from grcevidence.models import RunResult


class SinkError(RuntimeError):
    pass


class Sink(Protocol):
    name: str

    def write(self, run: RunResult) -> int:
        """Persist the run. Returns the number of objects/requests written. Raises SinkError."""
        ...
