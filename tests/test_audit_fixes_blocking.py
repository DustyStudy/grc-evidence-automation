from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
from botocore.exceptions import ClientError

from grcevidence.catalog import FRAMEWORKS
from grcevidence.models import Evidence, Status
from grcevidence.report import rollup, verify_run
from grcevidence.runner import Config, ConfigError, _access_error, deliver, run
from grcevidence.sinks import HttpSink, LocalSink

NOW = datetime(2026, 9, 20, 6, 0, tzinfo=UTC)


def _run(**over):
    raw = {"regions": ["us-east-1"], "collectors": {"include": ["aws.kms_rotation"]}}
    raw.update(over)
    return run(Config.from_dict(raw), now=NOW)


# ------------------------------------------------- fix 1: account access error is never a pass
def test_rollup_account_access_error_overrides_pass_from_another_account():
    passing = Evidence(
        "aws.x",
        "aws",
        "t",
        "111111111111",
        "r",
        "now",
        Status.PASS,
        "s",
        [],
        {},
        {"soc2": ["CC6.1"]},
    ).seal()
    blocked = _access_error("222222222222", RuntimeError("AccessDenied"), NOW)
    rows = {r.control: r for r in rollup([passing], "soc2")}
    assert rows["CC6.1"].status == "pass" and rows["CC1.1"].status == "no_automated_evidence"

    rows = {r.control: r for r in rollup([passing, blocked], "soc2")}
    assert rows["CC6.1"].status == "error"
    assert "aws.account_access" in rows["CC6.1"].evidence
    assert any("AccessDenied" in f for f in rows["CC6.1"].failing)


def test_run_with_one_unreachable_account_has_no_passing_control_in_any_framework():
    # The second account is the caller's own (reachable); the first id does not match it.
    result = _run(accounts=[{"id": "999999999999"}, {}])
    assert {e.collector for e in result.evidence} == {"aws.account_access", "aws.kms_rotation"}
    for framework in FRAMEWORKS:
        assert {r.status for r in rollup(result.evidence, framework)} <= {"error", "fail"}


# ------------------------------------------------------ fix 2: collector errors fail the Lambda
def test_lambda_handler_raises_after_delivery_when_a_collector_errored(monkeypatch, tmp_path):
    from grcevidence.collectors.aws.monitoring import CloudTrail
    from grcevidence.lambda_handler import handler

    monkeypatch.setattr(
        CloudTrail, "collect", lambda self, ctx: (_ for _ in ()).throw(KeyError("x"))
    )
    cfg = {
        "regions": ["us-east-1"],
        "collectors": {"include": ["aws.cloudtrail"]},
        "sinks": [{"type": "local", "path": str(tmp_path)}],
    }
    monkeypatch.setenv("GRC_CONFIG", json.dumps(cfg))
    with pytest.raises(RuntimeError, match=r"1 evidence record\(s\) have status error in run \d"):
        handler({})
    assert verify_run(tmp_path).problems == []  # the error record was still delivered


# ------------------------------------------------------------- fix 3: sink isolation in deliver
class _BrokenSink:
    name = "broken"

    def __init__(self, exc: Exception) -> None:
        self.exc = exc

    def write(self, run):
        raise self.exc


@pytest.mark.parametrize(
    "exc",
    [
        KeyError("token"),
        AttributeError("'int' object has no attribute 'partition'"),
        ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "no" + "x" * 500}},
            "GetSecretValue",
        ),
    ],
)
def test_deliver_isolates_any_sink_exception_and_still_writes_later_sinks(tmp_path, exc):
    result = deliver(_run(), [_BrokenSink(exc), LocalSink(tmp_path)])  # type: ignore[list-item]
    failure = result.failed_sinks["broken"]
    assert failure.startswith(f"failed: {type(exc).__name__}: ")
    assert len(failure) <= 200 + len(f"failed: {type(exc).__name__}: ")
    assert result.sink_results[LocalSink(tmp_path).name] == "ok"
    assert verify_run(tmp_path).problems == []


def test_deliver_does_not_swallow_keyboard_interrupt(tmp_path):
    with pytest.raises(KeyboardInterrupt):
        deliver(_run(), [_BrokenSink(KeyboardInterrupt())])  # type: ignore[list-item]


def test_http_sink_failure_never_echoes_the_token(monkeypatch, tmp_path):
    # http.client rejects a header value with a newline and quotes the value in its ValueError.
    monkeypatch.setenv("INGEST_TOKEN", "s3cr3t-value\nx")
    sink = HttpSink(
        "http://127.0.0.1:9/ingest",
        allow_insecure_http=True,
        auth={"type": "bearer", "token": "env:INGEST_TOKEN"},
    )
    result = deliver(_run(), [sink, LocalSink(tmp_path)])
    assert "ValueError" in result.failed_sinks[sink.name]
    assert "s3cr3t" not in json.dumps(result.sink_results)
    assert verify_run(tmp_path).problems == []


# ------------------------------------------------------------- fix 4: no GCP from the Lambda
def test_lambda_handler_rejects_gcp_projects_before_collecting(monkeypatch, tmp_path):
    from grcevidence.lambda_handler import handler

    cfg = {
        "gcp": {"projects": ["proj-1"]},
        "sinks": [{"type": "local", "path": str(tmp_path)}],
    }
    monkeypatch.setenv("GRC_CONFIG", json.dumps(cfg))
    with pytest.raises(ConfigError, match="GCP collectors are not packaged in the Lambda"):
        handler({})
    assert not list(tmp_path.iterdir())
