"""The fuzz targets, run as ordinary tests.

Coverage-guided fuzzing (``fuzz/run_fuzzer.py``) needs Atheris and time, so it runs in its own CI
job. Here every target runs on its checked-in seed corpus plus a deterministic batch of random
inputs, so the invariants are enforced on every change even without a fuzzing engine.
"""

from __future__ import annotations

import random
from pathlib import Path
from types import SimpleNamespace

import pytest

from fuzz import targets
from fuzz.targets import TARGETS, Reader

CORPUS = Path(__file__).resolve().parents[1] / "fuzz" / "corpus"
RANDOM_INPUTS = 250


def _random_inputs(name: str, count: int = RANDOM_INPUTS) -> list[bytes]:
    rng = random.Random(f"grc-{name}")
    return [bytes(rng.randrange(256) for _ in range(rng.randrange(0, 200))) for _ in range(count)]


@pytest.mark.parametrize("name", sorted(TARGETS))
def test_target_holds_on_its_seed_corpus_and_random_inputs(name):
    seeds = sorted((CORPUS / name).glob("*"))
    assert seeds, f"fuzz/corpus/{name} has no seed inputs"
    for data in [p.read_bytes() for p in seeds] + _random_inputs(name):
        TARGETS[name](data)


def test_the_runner_lists_every_target_and_compiles():
    source = (Path(__file__).resolve().parents[1] / "fuzz" / "run_fuzzer.py").read_text(
        encoding="utf-8"
    )
    compile(source, "run_fuzzer.py", "exec")
    assert "import atheris" in source
    assert set(TARGETS) == {"evidence", "verify", "report", "config", "secrets", "http_sink"}


def test_reader_never_raises_on_any_input():
    for data in [b"", b"\x00", b"\xff" * 5, bytes(range(256))]:
        r = Reader(data)
        r.text(), r.json_value(odd_keys=True), r.flag(), r.below(0), r.choice([1, 2, 3])


# ---------------------------------------------- the targets can actually fail
# A fuzz target that cannot fail proves nothing, so break the code under test in the way the
# invariant guards against and confirm the target notices.


def _fails_within(name: str, exc=AssertionError, budget: int = 1500) -> None:
    for data in _random_inputs(name, budget):
        try:
            TARGETS[name](data)
        except exc:
            return
    pytest.fail(f"target {name!r} did not detect the injected bug in {budget} inputs")


def test_evidence_target_detects_a_hash_that_ignores_content(monkeypatch):
    monkeypatch.setattr(targets.Evidence, "content_hash", lambda self: "constant")
    _fails_within("evidence")


def test_verify_target_detects_a_verifier_that_misses_tampering(monkeypatch):
    monkeypatch.setattr(targets, "verify_run", lambda path: [])
    _fails_within("verify")


def test_report_target_detects_unescaped_markdown(monkeypatch):
    monkeypatch.setattr(
        targets, "report_markdown", lambda *a, **k: "| a | b |\n| [x](https://attacker.example) |\n"
    )
    _fails_within("report")


def test_config_target_detects_a_loader_that_crashes(monkeypatch):
    def crash(raw):
        raise TypeError("not iterable")

    monkeypatch.setattr(targets.Config, "from_dict", crash)
    _fails_within("config", exc=TypeError)


def test_secrets_target_detects_a_resolver_that_returns_empty(monkeypatch):
    monkeypatch.setattr(targets, "resolve_secret", lambda ref, session=None: "")
    _fails_within("secrets")


def test_http_sink_target_detects_a_sink_built_for_plain_http_without_opt_in(monkeypatch):
    monkeypatch.setattr(
        targets, "build_sinks", lambda specs: [SimpleNamespace(url="http://ingest.example.com/x")]
    )
    _fails_within("http_sink")
