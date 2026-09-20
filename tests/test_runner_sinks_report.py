from __future__ import annotations

import http.server
import json
import threading
from datetime import UTC, datetime

import boto3
import pytest

from grcevidence import cli
from grcevidence.models import RunManifest, Status
from grcevidence.report import latest_run_dir, load_run, report_markdown, rollup, verify_run
from grcevidence.runner import Config, ConfigError, build_sinks, deliver, run
from grcevidence.secrets import SecretError, resolve_secret
from grcevidence.sinks import HttpSink, LocalSink, S3Sink, SinkError

NOW = datetime(2026, 9, 20, 6, 0, tzinfo=UTC)
FAST = ["aws.iam_password_policy", "aws.cloudtrail", "aws.network_exposure", "aws.kms_rotation"]


def _config(**over):
    raw = {"regions": ["us-east-1", "us-west-2"], "collectors": {"include": FAST}}
    raw.update(over)
    return Config.from_dict(raw)


# ------------------------------------------------------------------------ config
def test_config_is_strict():
    for bad in (
        {"acounts": []},
        {"collectors": {"incude": []}},
        {"accounts": [{"idd": "1"}]},
        {"parameters": {"nope": 1}},
    ):
        with pytest.raises(ConfigError):
            Config.from_dict(bad)
    with pytest.raises(ConfigError):
        Config.from_dict([])  # type: ignore[arg-type]


def test_config_from_yaml_and_json(tmp_path):
    f = tmp_path / "c.yaml"
    f.write_text(
        "regions: [eu-west-1]\ncollectors: {exclude: [aws.backups]}\nparameters: {max_access_key_age_days: 30}\n"
    )
    cfg = Config.from_file(f)
    assert cfg.regions == ["eu-west-1"] and cfg.parameters.max_access_key_age_days == 30
    assert Config.from_json('{"regions": ["us-east-2"]}').regions == ["us-east-2"]


def test_build_sinks_validation(tmp_path):
    assert len(build_sinks([{"type": "local", "path": str(tmp_path)}])) == 1
    for bad in (
        {"type": "ftp"},
        {"type": "local"},
        {"type": "http", "url": "http://insecure.example/x"},
    ):
        with pytest.raises(ConfigError):
            build_sinks([bad])


# -------------------------------------------------------------------------- run
def test_run_scopes_global_once_and_regional_per_region():
    result = run(_config(), now=NOW)
    ids = [e.id for e in result.evidence]
    acct = result.manifest.accounts[0]
    assert ids.count(f"aws.cloudtrail/{acct}/global") == 1
    assert (
        f"aws.network_exposure/{acct}/us-west-2" in ids
        and f"aws.network_exposure/{acct}/us-east-1" in ids
    )
    assert all(e.verify() for e in result.evidence)
    assert result.manifest.verify() and result.manifest.counts == {
        s: sum(1 for e in result.evidence if e.status.value == s) for s in result.manifest.counts
    }
    assert result.manifest.started_at.startswith("2026-09-20T06:00:00")


def test_run_assumes_role_and_records_target_account():
    cfg = _config(
        accounts=[
            {
                "id": "123456789012",
                "role_arn": "arn:aws:iam::123456789012:role/GrcEvidenceReader",
                "external_id": "ext-1",
                "regions": ["us-east-1"],
            },
        ],
        collectors={"include": ["aws.iam_password_policy"]},
    )
    result = run(cfg, now=NOW)
    assert result.manifest.accounts == ["123456789012"]
    assert result.evidence[0].account == "123456789012"


def test_run_account_mismatch_yields_error_evidence_not_silence():
    cfg = _config(
        accounts=[{"id": "999999999999"}], collectors={"include": ["aws.iam_password_policy"]}
    )
    result = run(cfg, now=NOW)
    assert len(result.evidence) == 1
    ev = result.evidence[0]
    assert ev.collector == "aws.account_access" and ev.status == Status.ERROR
    assert "999999999999" in ev.findings[0].message


def test_run_isolates_a_failing_collector(monkeypatch):
    from grcevidence.collectors.aws.monitoring import CloudTrail

    monkeypatch.setattr(
        CloudTrail, "collect", lambda self, ctx: (_ for _ in ()).throw(KeyError("x"))
    )
    result = run(_config(), now=NOW)
    statuses = {e.collector: e.status for e in result.evidence}
    assert statuses["aws.cloudtrail"] == Status.ERROR
    assert statuses["aws.iam_password_policy"] == Status.FAIL  # others still ran


def test_run_gcp_projects_use_injected_clients():
    from tests.test_models_catalog_gcp import FakeClients, _bucket

    cfg = Config.from_dict(
        {"gcp": {"projects": ["proj-1"]}, "collectors": {"include": ["gcp.storage_buckets"]}}
    )
    result = run(cfg, now=NOW, gcp_clients=FakeClients([_bucket("b", True, "enforced")]))
    assert [e.id for e in result.evidence] == ["gcp.storage_buckets/proj-1/global"]
    assert result.manifest.accounts == ["gcp:proj-1"] and result.evidence[0].status == Status.PASS


# ----------------------------------------------------------------- local + report
def test_local_sink_report_and_verify_roundtrip(tmp_path):
    result = deliver(run(_config(), now=NOW), [LocalSink(tmp_path)])
    assert result.sink_results and not result.failed_sinks
    run_dir = latest_run_dir(tmp_path)
    assert (run_dir / "manifest.json").exists()
    assert verify_run(tmp_path) == []

    manifest, evidence = load_run(tmp_path)
    assert manifest.run_id == result.manifest.run_id and len(evidence) == len(result.evidence)

    rows = {r.control: r for r in rollup(evidence, "soc2")}
    assert rows["CC7.2"].status == "fail"  # no CloudTrail in an empty account
    assert rows["CC1.1"].status == "no_automated_evidence"
    md = report_markdown(manifest, evidence, "soc2")
    assert "triage view" in md and "is *not* a pass" in md and "| CC7.2 |" in md
    with pytest.raises(ValueError):
        rollup(evidence, "hipaa")


def test_verify_detects_tampering_missing_and_extra_files(tmp_path):
    deliver(run(_config(), now=NOW), [LocalSink(tmp_path)])
    run_dir = latest_run_dir(tmp_path)
    files = sorted(p for p in run_dir.glob("*.json") if p.name != "manifest.json")

    doc = json.loads(files[0].read_text())
    doc["status"] = "pass"
    doc["summary"] = "edited"
    files[0].write_text(json.dumps(doc))
    assert any("sha256" in p for p in verify_run(tmp_path))

    files[1].unlink()
    (run_dir / "rogue.json").write_text("{}")
    problems = " ".join(verify_run(tmp_path))
    assert "missing" in problems and "not in manifest" in problems

    m = json.loads((run_dir / "manifest.json").read_text())
    m["counts"] = {"pass": 999}
    (run_dir / "manifest.json").write_text(json.dumps(m))
    assert "manifest hash" in " ".join(verify_run(tmp_path))


def test_rollup_precedence_error_is_not_pass():
    from grcevidence.models import Evidence, Finding, Severity

    def ev(status):
        return Evidence(
            "aws.x",
            "aws",
            "t",
            "1",
            "r",
            "now",
            status,
            "s",
            [Finding("r", "m", Severity.LOW)] if status != Status.PASS else [],
            {},
            {"soc2": ["CC6.1"]},
        ).seal()

    def status(*sts):
        return next(r.status for r in rollup([ev(s) for s in sts], "soc2") if r.control == "CC6.1")

    assert status(Status.PASS, Status.FAIL) == "fail"
    assert status(Status.PASS, Status.ERROR) == "error"
    assert status(Status.PASS) == "pass"
    assert status(Status.NOT_APPLICABLE) == "not_applicable"


def test_latest_run_dir_errors_when_empty(tmp_path):
    with pytest.raises(FileNotFoundError):
        latest_run_dir(tmp_path)


# --------------------------------------------------------------------------- S3
def test_s3_sink_writes_encrypted_objects_manifest_last():
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="evidence-bucket")
    result = run(_config(), now=NOW)
    sink = S3Sink("evidence-bucket", prefix="grc", kms_key_id=None, region="us-east-1")
    n = sink.write(result)
    keys = [o["Key"] for o in s3.list_objects_v2(Bucket="evidence-bucket")["Contents"]]
    assert n == len(keys) == len(result.evidence) + 1
    base = f"grc/dt=2026-09-20/{result.manifest.run_id}/"
    assert all(k.startswith(base) for k in keys) and base + "manifest.json" in keys
    head = s3.head_object(Bucket="evidence-bucket", Key=base + "manifest.json")
    assert (
        head["ServerSideEncryption"] == "AES256"
        and head["Metadata"]["sha256"] == result.manifest.sha256
    )
    body = json.loads(
        s3.get_object(Bucket="evidence-bucket", Key=base + "manifest.json")["Body"].read()
    )
    assert RunManifest.from_dict(body).verify()


def test_s3_sink_kms_and_failure_is_sinkerror():
    kms = boto3.client("kms", region_name="us-east-1")
    key = kms.create_key()["KeyMetadata"]["KeyId"]
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="kms-bucket")
    result = run(_config(collectors={"include": ["aws.kms_rotation"]}), now=NOW)
    S3Sink("kms-bucket", kms_key_id=key).write(result)
    obj = s3.list_objects_v2(Bucket="kms-bucket")["Contents"][0]["Key"]
    assert s3.head_object(Bucket="kms-bucket", Key=obj)["ServerSideEncryption"] == "aws:kms"
    with pytest.raises(SinkError):
        S3Sink("no-such-bucket").write(result)


def test_deliver_continues_after_a_failing_sink(tmp_path):
    result = run(_config(collectors={"include": ["aws.kms_rotation"]}), now=NOW)
    deliver(result, [S3Sink("no-such-bucket"), LocalSink(tmp_path)])
    assert list(result.failed_sinks) == ["s3://no-such-bucket/evidence"]
    assert verify_run(tmp_path) == []


# -------------------------------------------------------------------------- HTTP
class _Server:
    def __init__(self, script):
        self.script = list(script)  # list of (status, headers, body)
        self.requests: list[dict] = []
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                length = int(self.headers.get("Content-Length", 0))
                raw = self.rfile.read(length)
                outer.requests.append(
                    {"path": self.path, "headers": dict(self.headers), "body": raw}
                )
                status, headers, body = outer.script.pop(0) if outer.script else (200, {}, b"{}")
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        self.httpd = http.server.HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.httpd.server_port}"

    def close(self):
        self.httpd.shutdown()


@pytest.fixture
def server():
    made = []

    def make(script=()):
        s = _Server(script)
        made.append(s)
        return s

    yield make
    for s in made:
        s.close()


def _small_run():
    return run(
        _config(collectors={"include": ["aws.kms_rotation"]}, regions=["us-east-1"]), now=NOW
    )


def test_http_sink_https_and_url_rules():
    for bad in ("http://example.com/x", "https://user:pw@example.com/x", "ftp://example.com"):
        with pytest.raises(SinkError):
            HttpSink(bad)
    with pytest.raises(SinkError):
        HttpSink("https://example.com/x", format="csv")


def test_http_bundle_bearer_idempotency(server, monkeypatch):
    monkeypatch.setenv("INGEST_TOKEN", "tok-123")
    srv = server()
    sink = HttpSink(
        srv.url + "/v1/evidence",
        allow_insecure_http=True,
        auth={"type": "bearer", "token": "env:INGEST_TOKEN"},
    )
    result = _small_run()
    assert sink.write(result) == 1
    (req,) = srv.requests
    assert req["headers"]["Authorization"] == "Bearer tok-123"
    assert req["headers"]["Idempotency-Key"] == result.manifest.sha256
    body = json.loads(req["body"])
    assert body["run"]["run_id"] == result.manifest.run_id and len(body["evidence"]) == len(
        result.evidence
    )


def test_http_per_evidence_and_template(server):
    srv = server()
    result = _small_run()
    sink = HttpSink(
        srv.url,
        allow_insecure_http=True,
        format="per_evidence",
        payload_template={"source": "grc", "data": "$payload"},
    )
    assert sink.write(result) == len(result.evidence)
    body = json.loads(srv.requests[0]["body"])
    assert body["source"] == "grc" and body["data"]["run_id"] == result.manifest.run_id


def test_http_retries_5xx_and_429_then_succeeds(server):
    srv = server([(503, {}, b"down"), (429, {"Retry-After": "0"}, b"slow"), (200, {}, b"{}")])
    sleeps: list[float] = []
    sink = HttpSink(srv.url, allow_insecure_http=True, backoff=0.5, sleep=sleeps.append)
    sink.write(_small_run())
    assert len(srv.requests) == 3 and sleeps == [0.5, 0.0]  # exponential backoff, then Retry-After


def test_http_gives_up_after_retries_and_4xx_fails_fast(server):
    srv = server([(500, {}, b"x")] * 3)
    sink = HttpSink(srv.url, allow_insecure_http=True, retries=2, sleep=lambda s: None)
    with pytest.raises(SinkError, match="failed after 3 attempts"):
        sink.write(_small_run())
    assert len(srv.requests) == 3

    srv2 = server([(403, {}, b'{"error":"forbidden"}')])
    with pytest.raises(SinkError, match="HTTP 403"):
        HttpSink(srv2.url, allow_insecure_http=True, sleep=lambda s: None).write(_small_run())
    assert len(srv2.requests) == 1  # no retry on client errors


def test_http_never_follows_redirects_or_leaks_auth(server, monkeypatch):
    monkeypatch.setenv("INGEST_TOKEN", "tok-123")
    target = server()
    redirector = server([(302, {"Location": target.url + "/steal"}, b"")])
    sink = HttpSink(
        redirector.url,
        allow_insecure_http=True,
        auth={"type": "bearer", "token": "env:INGEST_TOKEN"},
        sleep=lambda s: None,
    )
    with pytest.raises(SinkError, match="HTTP 302"):
        sink.write(_small_run())
    assert target.requests == []


def test_http_oauth_client_credentials_caches_token(server, monkeypatch):
    monkeypatch.setenv("CID", "client-1")
    monkeypatch.setenv("CSEC", "secret-1")
    srv = server([(200, {}, json.dumps({"access_token": "at-9", "expires_in": 3600}).encode())])
    sink = HttpSink(
        srv.url + "/ingest",
        allow_insecure_http=True,
        format="per_evidence",
        auth={
            "type": "oauth2_client_credentials",
            "token_url": srv.url + "/token",
            "client_id": "env:CID",
            "client_secret": "env:CSEC",
            "scope": "evidence.write",
        },
    )
    result = _small_run()
    sink.write(result)
    token_req, *posts = srv.requests
    assert (
        token_req["path"] == "/token"
        and b"grant_type=client_credentials" in token_req["body"]
        and b"scope=evidence.write" in token_req["body"]
    )
    assert all(p["headers"]["Authorization"] == "Bearer at-9" for p in posts) and len(posts) == len(
        result.evidence
    )
    sink.write(result)  # second write reuses the cached token
    assert sum(1 for r in srv.requests if r["path"] == "/token") == 1


def test_http_dry_run_sends_nothing_and_size_cap(server):
    srv = server()
    assert HttpSink(srv.url, allow_insecure_http=True, dry_run=True).write(_small_run()) == 1
    assert srv.requests == []
    import grcevidence.sinks.http as h

    old = h.MAX_BODY_BYTES
    h.MAX_BODY_BYTES = 10
    try:
        with pytest.raises(SinkError, match="per_evidence"):
            HttpSink(srv.url, allow_insecure_http=True).write(_small_run())
    finally:
        h.MAX_BODY_BYTES = old


# ----------------------------------------------------------------------- secrets
def test_secret_resolution_env_secretsmanager_ssm(monkeypatch):
    monkeypatch.setenv("MY_TOKEN", "abc")
    assert resolve_secret("env:MY_TOKEN") == "abc"
    sm = boto3.client("secretsmanager", region_name="us-east-1")
    sm.create_secret(Name="grc/token", SecretString="plain-secret")
    sm.create_secret(Name="grc/json", SecretString=json.dumps({"api_key": "k-1"}))
    assert resolve_secret("secretsmanager:grc/token") == "plain-secret"
    assert resolve_secret("secretsmanager:grc/json#api_key") == "k-1"
    boto3.client("ssm", region_name="us-east-1").put_parameter(
        Name="/grc/t", Value="ssm-val", Type="SecureString"
    )
    assert resolve_secret("ssm:/grc/t") == "ssm-val"


@pytest.mark.parametrize(
    "ref",
    [
        "literal-secret",
        "env:",
        "env:NOT_SET_ANYWHERE",
        "vault:x",
        "secretsmanager:grc/json#missing",
    ],
)
def test_secret_resolution_rejects_literals_and_missing(ref):
    boto3.client("secretsmanager", region_name="us-east-1").create_secret(
        Name="grc/json", SecretString=json.dumps({"a": 1})
    )
    with pytest.raises(SecretError):
        resolve_secret(ref)


# -------------------------------------------------------------- Lambda + CLI
def test_lambda_handler_dry_run_and_delivery(monkeypatch, tmp_path):
    from grcevidence.lambda_handler import handler

    cfg = {
        "regions": ["us-east-1"],
        "collectors": {"include": ["aws.kms_rotation"]},
        "sinks": [{"type": "local", "path": str(tmp_path)}],
    }
    monkeypatch.setenv("GRC_CONFIG", json.dumps(cfg))
    dry = handler({"dry_run": True})
    assert dry["dry_run"] and not list(tmp_path.iterdir())
    out = handler({})
    assert out["counts"] and list(out["sinks"].values()) == ["ok"] and verify_run(tmp_path) == []
    subset = handler({"collectors": ["aws.iam_password_policy"]})
    assert subset["counts"] == {"fail": 1}


def test_lambda_handler_refuses_to_run_without_sinks(monkeypatch):
    from grcevidence.lambda_handler import handler

    monkeypatch.setenv("GRC_CONFIG", json.dumps({"collectors": {"include": ["aws.kms_rotation"]}}))
    with pytest.raises(ConfigError, match="no sinks"):
        handler({})


def test_lambda_handler_raises_when_a_sink_fails(monkeypatch):
    from grcevidence.lambda_handler import handler

    cfg = {
        "collectors": {"include": ["aws.kms_rotation"]},
        "sinks": [{"type": "s3", "bucket": "missing-bucket"}],
    }
    monkeypatch.setenv("GRC_CONFIG", json.dumps(cfg))
    with pytest.raises(RuntimeError, match="delivery failed"):
        handler({})


def test_cli_end_to_end(tmp_path, capsys):
    cfgfile = tmp_path / "grc.yaml"
    cfgfile.write_text(
        "regions: [us-east-1]\ncollectors: {include: [aws.iam_password_policy, aws.cloudtrail]}\n"
    )
    out = tmp_path / "out"
    assert cli.main(["collect", "--config", str(cfgfile), "--output", str(out)]) == 0
    assert (
        cli.main(
            [
                "collect",
                "--config",
                str(cfgfile),
                "--output",
                str(tmp_path / "o2"),
                "--fail-on-findings",
            ]
        )
        == 1
    )
    assert cli.main(["verify", str(out)]) == 0
    assert cli.main(["report", str(out), "--framework", "iso27001"]) == 0
    assert cli.main(["report", str(out), "--format", "json"]) == 0
    text = capsys.readouterr().out
    assert "A.5.17" in text and '"control": "CC7.2"' in text
    # tamper
    victim = next(p for p in latest_run_dir(out).glob("*.json") if p.name != "manifest.json")
    victim.write_text(victim.read_text().replace("fail", "pass"))
    assert cli.main(["verify", str(out)]) == 1
    assert cli.main(["collect", "--config", str(cfgfile)]) == 2  # no sink
    assert cli.main(["collect", "--config", str(cfgfile), "--dry-run"]) == 0
    assert cli.main(["collect", "--only", "aws.nope", "--dry-run"]) == 2


def test_cli_catalog_commands(capsys):
    assert cli.main(["collectors"]) == 0
    assert cli.main(["coverage", "--check"]) == 0
    assert cli.main(["coverage"]) == 0
    assert cli.main(["coverage", "--framework", "nist_800_53"]) == 0
    assert cli.main(["permissions"]) == 0
    out = capsys.readouterr().out
    assert (
        "aws.cloudtrail" in out
        and "gap: A1.1" in out
        and "cloudtrail:DescribeTrails" in out
        and "sts:GetCallerIdentity" in out
    )
    policy = json.loads(out[out.index('{\n  "Version"') :])
    assert (
        policy["Statement"][0]["Effect"] == "Allow"
        and "iam:*" not in policy["Statement"][0]["Action"]
    )


# ------------------------------------------------- hardening: config, manifest, report
def test_lambda_handler_ignores_no_event_config_but_rejects_an_event_supplied_one(
    monkeypatch, tmp_path
):
    """Anyone who can invoke the function must not be able to swap in their own sinks/secrets."""
    from grcevidence.lambda_handler import handler

    good = {
        "collectors": {"include": ["aws.kms_rotation"]},
        "sinks": [{"type": "local", "path": str(tmp_path)}],
    }
    monkeypatch.setenv("GRC_CONFIG", json.dumps(good))
    monkeypatch.delenv("GRC_ALLOW_EVENT_CONFIG", raising=False)

    hostile = {
        "collectors": {"include": ["aws.kms_rotation"]},
        "sinks": [
            {
                "type": "http",
                "url": "https://attacker.example/collect",
                "auth": {"type": "bearer", "token": "secretsmanager:prod/db-password"},
            }
        ],
    }
    with pytest.raises(ConfigError, match="supplied its own config"):
        handler({"config": hostile})
    assert not list(tmp_path.iterdir())  # nothing collected or written


def test_lambda_handler_event_config_can_be_explicitly_enabled(monkeypatch, tmp_path):
    from grcevidence.lambda_handler import handler

    monkeypatch.setenv("GRC_CONFIG", "{}")
    monkeypatch.setenv("GRC_ALLOW_EVENT_CONFIG", "true")
    cfg = {
        "collectors": {"include": ["aws.kms_rotation"]},
        "sinks": [{"type": "local", "path": str(tmp_path)}],
    }
    out = handler({"config": cfg})
    assert list(out["sinks"].values()) == ["ok"]


@pytest.mark.parametrize(
    "bad",
    ["../outside.json", "/etc/passwd", "sub/dir.json", "..\\outside.json", "manifest.json", ""],
)
def test_manifest_cannot_point_outside_its_run_directory(tmp_path, bad):
    deliver(run(_config(), now=NOW), [LocalSink(tmp_path)])
    run_dir = latest_run_dir(tmp_path)
    outside = tmp_path / "outside.json"
    outside.write_text("{}")

    m = json.loads((run_dir / "manifest.json").read_text())
    m["evidence"][0]["file"] = bad
    (run_dir / "manifest.json").write_text(json.dumps(m))

    problems = " ".join(verify_run(tmp_path))
    assert "unsafe evidence file name" in problems
    with pytest.raises(ValueError, match="unsafe evidence file name"):
        load_run(tmp_path)


def test_report_escapes_evidence_text_so_it_cannot_break_out_of_a_cell():
    from grcevidence.catalog import controls_for
    from grcevidence.models import Evidence, Finding, Severity

    ev = Evidence(
        collector="aws.iam_mfa",
        provider="aws",
        title="t",
        account="123456789012",
        region="global",
        collected_at="2026-09-20T06:00:00+00:00",
        status=Status.FAIL,
        summary="s",
        findings=[
            Finding("a|b", "line1\n| injected | row |\n<img src=x onerror=alert(1)>", Severity.HIGH)
        ],
        controls=controls_for("aws.iam_mfa"),
    ).seal()
    manifest = RunManifest(
        run_id="r|1",
        started_at="2026-09-20T06:00:00+00:00",
        finished_at="2026-09-20T06:00:01+00:00",
        tool_version="0",
        accounts=["<b>x</b>"],
        counts={"fail": 1},
        evidence=[],
    ).seal()
    md = report_markdown(manifest, [ev], "soc2")
    assert "<img" not in md and "<b>" not in md
    assert "&lt;img" in md
    # every table row must still have the header's number of cells (no injected extra rows)
    for line in md.splitlines():
        if line.startswith("|"):
            assert line.count("|") in (3, 6)  # summary table or control table, nothing else
