from __future__ import annotations

import http.client
import io
import json
import sys
import urllib.error

import pytest

from grcevidence import cli
from grcevidence.lambda_handler import handler
from grcevidence.runner import Config, ConfigError
from grcevidence.sinks import HttpSink, SinkError
from grcevidence.sinks import http as http_sink
from scripts import lock

LITERAL = "sk-live-literal-value"


def _http(auth):
    return {"sinks": [{"type": "http", "url": "https://ingest.example.com/v1", "auth": auth}]}


# --------------------------------------------------- item 1: literals are rejected at load
@pytest.mark.parametrize(
    ("auth", "field"),
    [
        ({"type": "bearer", "token": LITERAL}, "token"),
        ({"type": "bearer", "token": "vendor:" + LITERAL}, "token"),  # unknown scheme
        ({"type": "bearer", "token": "env:"}, "token"),
        ({"type": "bearer", "token": 12345}, "token"),
        (
            {
                "type": "oauth2_client_credentials",
                "token_url": "https://id.example.com/token",
                "client_id": "env:ID",
                "client_secret": LITERAL,
            },
            "client_secret",
        ),
        (
            {
                "type": "oauth2_client_credentials",
                "token_url": "https://id.example.com/token",
                "client_id": LITERAL,
                "client_secret": "env:SECRET",
            },
            "client_id",
        ),
    ],
)
def test_literal_secret_fails_at_config_load_without_echoing_it(auth, field):
    with pytest.raises(ConfigError) as err:
        Config.from_dict(_http(auth))
    message = str(err.value)
    assert "sinks[0]" in message and field in message
    assert LITERAL not in message and "12345" not in message


def test_references_and_literal_headers_still_load():
    for ref in ("env:INGEST_TOKEN", "secretsmanager:grc/ingest#token", "ssm:/grc/ingest-token"):
        raw = _http({"type": "bearer", "token": ref})
        raw["sinks"][0]["headers"] = {"X-Api-Version": "2026-01"}  # literal by design
        assert Config.from_dict(raw).sinks == raw["sinks"]


def test_dry_run_with_a_literal_token_fails(monkeypatch, tmp_path, capsys):
    raw = _http({"type": "bearer", "token": LITERAL})
    cfgfile = tmp_path / "config.json"  # JSON is valid YAML
    cfgfile.write_text(json.dumps(raw), encoding="utf-8")
    assert cli.main(["collect", "--config", str(cfgfile), "--dry-run"]) == 2
    captured = capsys.readouterr()
    assert "secret reference" in captured.err
    assert LITERAL not in captured.err + captured.out

    monkeypatch.setenv("GRC_CONFIG", json.dumps(raw))
    with pytest.raises(ConfigError, match="secret reference"):
        handler({"dry_run": True})


# ------------------------------------------- item 2: a broken response read is retried
class _Opener:
    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.requests = []

    def open(self, req, timeout=None):
        self.requests.append(req)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return io.BytesIO(outcome)  # a context manager with read(), like the real response


def _sink(sleeps):
    return HttpSink("https://ingest.example.com/v1", retries=2, backoff=0.5, sleep=sleeps.append)


def test_http_exception_is_retried_with_the_same_idempotency_key(monkeypatch):
    opener = _Opener([http.client.IncompleteRead(b"par", 10), b"ok"])
    monkeypatch.setattr(http_sink, "_OPENER", opener)
    sleeps: list[float] = []
    body = _sink(sleeps)._request(
        "https://ingest.example.com/v1", b"{}", "application/json", None, "idem-1", {}
    )
    assert body == b"ok"
    assert sleeps == [0.5]  # the same backoff as a 5xx on the first attempt
    assert [r.get_header("Idempotency-key") for r in opener.requests] == ["idem-1", "idem-1"]


def test_http_exception_gives_up_after_retries_and_4xx_still_fails_fast(monkeypatch):
    opener = _Opener([http.client.IncompleteRead(b"")] * 3)
    monkeypatch.setattr(http_sink, "_OPENER", opener)
    sleeps: list[float] = []
    with pytest.raises(SinkError, match="failed after 3 attempts: IncompleteRead"):
        _sink(sleeps)._request("https://ingest.example.com/v1", b"{}", "a/b", None, "k", {})
    assert sleeps == [0.5, 1.0]

    rejected = urllib.error.HTTPError("https://ingest.example.com/v1", 400, "Bad", None, None)  # type: ignore[arg-type]
    opener = _Opener([rejected])
    monkeypatch.setattr(http_sink, "_OPENER", opener)
    sleeps = []
    with pytest.raises(SinkError, match="rejected: HTTP 400"):
        _sink(sleeps)._request("https://ingest.example.com/v1", b"{}", "a/b", None, "k", {})
    assert len(opener.requests) == 1 and sleeps == []


# ------------------------------------------------------------ item 3: lock.py --check
def test_lock_check_reports_drift_and_writes_nothing(monkeypatch, tmp_path, capsys):
    (tmp_path / "requirements").mkdir()
    committed = {name: tmp_path / f"{lock.REQ}{name}.txt" for name in ("runtime", "dev")}
    for path in committed.values():
        path.write_bytes(b"pkg==1.0\r\n")  # a CRLF checkout must not count as drift

    def fake_compile(name, inputs, upgrade, out=None):
        assert out is not None and tmp_path not in lock.Path(out).parents
        assert lock.Path(out).read_bytes() == b"pkg==1.0\r\n"  # seeded with the committed pins
        lock.Path(out).write_text("pkg==2.0\n" if name == "dev" else "pkg==1.0\n", newline="\n")

    monkeypatch.setattr(lock, "ROOT", tmp_path)
    monkeypatch.setattr(lock, "compile_lock", fake_compile)

    monkeypatch.setattr(sys, "argv", ["lock.py", "--check", "runtime"])
    assert lock.main() == 0

    monkeypatch.setattr(sys, "argv", ["lock.py", "--check", "runtime", "dev"])
    assert lock.main() == 1
    out = capsys.readouterr().out
    assert "requirements/requirements-dev.txt" in out and "requirements-runtime.txt" not in out
    assert all(path.read_bytes() == b"pkg==1.0\r\n" for path in committed.values())
    assert sorted(p.name for p in (tmp_path / "requirements").iterdir()) == [
        "requirements-dev.txt",
        "requirements-runtime.txt",
    ]
