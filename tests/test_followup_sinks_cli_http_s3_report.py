from __future__ import annotations

import json

import boto3
import pytest

from grcevidence import cli
from grcevidence.report import latest_run_dir
from grcevidence.runner import ConfigError, build_sinks, deliver, run
from grcevidence.sinks import HttpSink, LocalSink, S3Sink, SinkError
from tests.test_runner_sinks_report import NOW, _config, _small_run, server  # noqa: F401


# -------------------------------------------------------------------------- HTTP
def _oauth(token_url):
    return {
        "type": "oauth2_client_credentials",
        "token_url": token_url,
        "client_id": "env:CID",
        "client_secret": "env:CSEC",
    }


def test_http_custom_headers_go_to_the_ingest_host_only(server, monkeypatch):  # noqa: F811
    monkeypatch.setenv("CID", "client-1")
    monkeypatch.setenv("CSEC", "secret-1")
    srv = server([(200, {}, json.dumps({"access_token": "at-9"}).encode())])
    sink = HttpSink(
        srv.url + "/ingest",
        allow_insecure_http=True,
        headers={"X-Api-Key": "ingest-only"},
        auth=_oauth(srv.url + "/token"),
    )
    sink.write(_small_run())
    token_req, post = srv.requests
    assert token_req["path"] == "/token" and "X-Api-Key" not in token_req["headers"]
    assert token_req["headers"]["Content-Type"] == "application/x-www-form-urlencoded"
    assert post["headers"]["X-Api-Key"] == "ingest-only"


@pytest.mark.parametrize(
    "token_url", ["file:///etc/passwd", "ftp://example.com/t", "example.com/token", "", None, 7]
)
def test_http_token_url_scheme_is_checked_at_construction(token_url):
    for insecure in (False, True):
        with pytest.raises(SinkError, match="token_url"):
            HttpSink("https://example.com/x", allow_insecure_http=insecure, auth=_oauth(token_url))


def test_http_token_url_http_needs_the_insecure_opt_in():
    with pytest.raises(SinkError, match="token_url"):
        HttpSink("https://example.com/x", auth=_oauth("http://example.com/token"))
    HttpSink(
        "https://example.com/x", allow_insecure_http=True, auth=_oauth("http://example.com/token")
    )
    HttpSink("https://example.com/x", auth=_oauth("https://example.com/token"))
    with pytest.raises(ConfigError, match="token_url"):
        build_sinks([{"type": "http", "url": "https://example.com/x", "auth": _oauth("file:///x")}])


def test_http_errors_carry_no_query_string_or_response_body(server):  # noqa: F811
    srv = server([(403, {}, b'{"error":"body-secret-1"}')] + [(500, {}, b"body-secret-2")] * 2)
    url = srv.url + "/v1/evidence?probe_marker=zq-probe-7731"
    expected = srv.url + "/v1/evidence"
    for match in (f"POST {expected} rejected: HTTP 403 Forbidden$", "failed after 2 attempts"):
        sink = HttpSink(url, allow_insecure_http=True, retries=1, sleep=lambda s: None)
        with pytest.raises(SinkError, match=match) as err:
            sink.write(_small_run())
        message = str(err.value)
        assert expected in message and "HTTP " in message
        assert "zq-probe-7731" not in message and "?" not in message
        assert "body-secret" not in message
    assert "zq-probe-7731" not in sink.name


# --------------------------------------------------------------------------- S3
def test_s3_sink_sends_expected_bucket_owner_and_validates_it():
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="owned-bucket")
    for bad in ("12345", "12345678901a", 123456789012, ""):
        with pytest.raises(SinkError, match="expected_bucket_owner"):
            S3Sink("owned-bucket", expected_bucket_owner=bad)  # type: ignore[arg-type]
    with pytest.raises(ConfigError, match="expected_bucket_owner"):
        build_sinks([{"type": "s3", "bucket": "owned-bucket", "expected_bucket_owner": 1234}])

    seen: list[dict] = []
    for owner in (None, "123456789012"):
        sink = S3Sink("owned-bucket", prefix=f"p{owner}", expected_bucket_owner=owner)
        for op in ("PutObject", "ListObjectsV2", "GetObject"):
            sink._s3.meta.events.register(
                f"provide-client-params.s3.{op}", lambda params, **_: seen.append(params)
            )
        result = run(_config(collectors={"include": ["aws.kms_rotation"]}), now=NOW, sinks=[sink])
        sink.write(result)
        assert sink.latest_manifest(before="99999999") is not None
        assert seen and {p.get("ExpectedBucketOwner") for p in seen} == {owner}
        assert {"Body", "Delimiter", "Key"} <= {k for p in seen for k in p}  # all three calls
        seen.clear()


def test_s3_sink_never_overwrites_an_existing_key():
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="once-bucket")
    result = run(_config(collectors={"include": ["aws.kms_rotation"]}), now=NOW)
    sink = S3Sink("once-bucket")
    sink.write(result)
    key = next(
        o["Key"]
        for o in s3.list_objects_v2(Bucket="once-bucket")["Contents"]
        if not o["Key"].endswith("manifest.json")
    )
    before = s3.get_object(Bucket="once-bucket", Key=key)["Body"].read()
    with pytest.raises(SinkError, match="already exists"):
        sink.write(result)
    assert s3.get_object(Bucket="once-bucket", Key=key)["Body"].read() == before
    deliver(result, [sink])
    assert "already exists" in result.sink_results[sink.name]


# ----------------------------------------------------------------------- report
def _stored_run(tmp_path):
    deliver(run(_config(), now=NOW), [LocalSink(tmp_path)])
    return latest_run_dir(tmp_path)


def test_report_renders_a_clean_run(tmp_path, capsys):
    _stored_run(tmp_path)
    assert cli.main(["report", str(tmp_path)]) == 0
    out, err = capsys.readouterr()
    assert "| CC7.2 |" in out and err == ""


def test_report_refuses_a_tampered_run_unless_no_verify(tmp_path, capsys):
    run_dir = _stored_run(tmp_path)
    victim = next(p for p in sorted(run_dir.glob("*cloudtrail*.json")))
    doc = json.loads(victim.read_text())
    assert doc["status"] == "fail"
    doc["status"] = "pass"
    victim.write_text(json.dumps(doc))

    assert cli.main(["report", str(tmp_path)]) == 1
    out, err = capsys.readouterr()
    assert out == "" and "sha256" in err and "not rendered" in err and "--no-verify" in err

    assert cli.main(["report", str(tmp_path), "--no-verify"]) == 0
    out, err = capsys.readouterr()
    assert "| CC7.2 |" in out and err.startswith("warning:") and "NOT verified" in err


@pytest.mark.parametrize("flags", [[], ["--no-verify"]])
@pytest.mark.parametrize("content", ["{not json", "[]", '{"run_id": 5}', '{"evidence": [7]}'])
def test_report_malformed_manifest_is_a_clean_error(tmp_path, capsys, flags, content):
    run_dir = _stored_run(tmp_path)
    (run_dir / "manifest.json").write_text(content)
    code = cli.main(["report", str(tmp_path), *flags])  # must not raise
    out, err = capsys.readouterr()
    assert code == (2 if flags else 1)
    assert out == "" and "malformed" in err and "Traceback" not in err


def test_report_malformed_evidence_and_missing_run_are_clean_errors(tmp_path, capsys):
    assert cli.main(["report", str(tmp_path / "nope")]) == 2
    run_dir = _stored_run(tmp_path)
    next(p for p in run_dir.glob("*.json") if p.name != "manifest.json").write_text("[1]")
    assert cli.main(["report", str(tmp_path), "--no-verify"]) == 2
    out, err = capsys.readouterr()
    assert out == "" and "malformed" in err
