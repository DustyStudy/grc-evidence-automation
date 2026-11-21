"""Manifest signatures (KMS), the hash chain across runs, and what each run was judged against."""

from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import asdict
from datetime import timedelta

import boto3
import pytest
from botocore.exceptions import ClientError

from grcevidence import cli
from grcevidence.models import Evidence, RunManifest, Status, canonical_json, kms_region
from grcevidence.report import latest_run_dir, run_dirs, verify_run
from grcevidence.runner import Config, ConfigError, deliver, run
from grcevidence.sinks import LocalSink, S3Sink, SinkError
from tests.conftest import NOW

BUCKET = "evidence-store"


def _config(**over) -> Config:
    raw = {"regions": ["us-east-1"], "collectors": {"include": ["aws.iam_password_policy"]}}
    raw.update(over)
    return Config.from_dict(raw)


def _collect(sinks, minutes=0, **over):
    return deliver(run(_config(**over), now=NOW + timedelta(minutes=minutes), sinks=sinks), sinks)


def _signing_key() -> str:
    kms = boto3.client("kms", region_name="us-east-1")
    return kms.create_key(KeySpec="ECC_NIST_P256", KeyUsage="SIGN_VERIFY")["KeyMetadata"]["Arn"]


def _kms(key_id: str):
    return boto3.client("kms", region_name="us-east-1")


def _chain(root, n=3, **over):
    sink = LocalSink(root)
    return [_collect([sink], minutes=i, **over).manifest for i in range(n)]


def _rewrite(run_dir, edit, reseal=True):
    """Edit a stored manifest; with reseal the edit gets a valid hash (a capable forger)."""
    path = run_dir / "manifest.json"
    m = RunManifest.from_dict(json.loads(path.read_text(encoding="utf-8")))
    edit(m)
    if reseal:
        m.seal()
    path.write_text(json.dumps(m.to_dict()), encoding="utf-8")
    return m


def _legacy_run(root, run_id: str) -> dict:
    """A run stored by 0.1.x: schema 1.0, manifest hashed over the v1 field set only."""
    ev = Evidence(
        "aws.x", "aws", "t", "111111111111", "global", "2026-01-01T00:00:00+00:00",
        Status.PASS, "ok", schema_version="1.0",
    ).seal()  # fmt: skip
    body = {
        "run_id": run_id,
        "started_at": "2026-01-01T00:00:00+00:00",
        "finished_at": "2026-01-01T00:00:01+00:00",
        "tool_version": "0.1.1",
        "accounts": ["111111111111"],
        "counts": {"pass": 1},
        "evidence": [{"id": ev.id, "file": ev.filename, "status": "pass", "sha256": ev.sha256}],
        "schema_version": "1.0",
    }
    body["sha256"] = hashlib.sha256(canonical_json(body)).hexdigest()
    run_dir = root / run_id
    run_dir.mkdir(parents=True)
    (run_dir / ev.filename).write_text(json.dumps(ev.to_dict()), encoding="utf-8")
    (run_dir / "manifest.json").write_text(json.dumps(body), encoding="utf-8")
    return body


# ------------------------------------------------------------------------ config
def test_signing_config_is_validated():
    assert Config().signing_key_id is None and Config.from_dict({}).signing_key_id is None
    assert Config.from_dict({"signing": {"kms_key_id": "alias/grc"}}).signing_key_id == "alias/grc"
    for bad in (
        {"signing": "alias/grc"},
        {"signing": {"kms_key_id": "alias/grc", "algorithm": "RSA"}},
        {"signing": {}},
        {"signing": {"kms_key_id": "  "}},
        {"signing": {"kms_key_id": 5}},
    ):
        with pytest.raises(ConfigError, match="signing"):
            Config.from_dict(bad)


def test_kms_region_comes_from_an_arn_only():
    assert kms_region("arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/abc") == "us-gov-west-1"
    assert kms_region("arn:aws:kms:eu-west-1:111122223333:alias/grc") == "eu-west-1"
    assert kms_region("alias/grc") is None and kms_region("1234abcd-12ab") is None


# -------------------------------------------------------------------- run manifest
def test_manifest_records_what_the_run_was_judged_against(monkeypatch):
    monkeypatch.setenv("TOK", "first-value")
    raw = {
        "regions": ["us-east-1"],
        "collectors": {"include": ["aws.iam_password_policy", "aws.kms_rotation"]},
        "parameters": {"sensitive_ports": [22]},
        "sinks": [
            {
                "type": "http",
                "url": "https://ingest.example.com/x",
                "auth": {"type": "bearer", "token": "env:TOK"},
            }
        ],
    }
    m1 = run(Config.from_dict(raw), now=NOW).manifest
    assert m1.collectors == ["aws.iam_password_policy", "aws.kms_rotation"]
    assert m1.parameters["sensitive_ports"] == [22] and m1.parameters["password_min_length"] == 15
    assert m1.previous is None and m1.signature is None and m1.schema_version == "2.0"
    assert (
        m1.config_sha256
        == hashlib.sha256(canonical_json(asdict(Config.from_dict(raw)))).hexdigest()
    )
    # The config holds the secret's reference, not its value: rotating the secret changes nothing.
    monkeypatch.setenv("TOK", "rotated-value")
    assert run(Config.from_dict(raw), now=NOW).manifest.config_sha256 == m1.config_sha256
    raw["parameters"] = {"sensitive_ports": [22, 3389]}
    assert run(Config.from_dict(raw), now=NOW).manifest.config_sha256 != m1.config_sha256


def test_run_signs_the_manifest_and_kms_verifies_it(tmp_path):
    key = _signing_key()
    m = _collect([LocalSink(tmp_path)], signing={"kms_key_id": key}).manifest
    assert m.signature and m.signature["key_id"] == key
    assert m.signature["algorithm"] == "ECDSA_SHA_256"
    ok = verify_run(tmp_path, kms=_kms)
    assert ok and ok.signatures == 1 and ok.chain_checked
    assert any("--key-id" in n for n in ok.notes)  # unpinned: say so
    pinned = verify_run(tmp_path, kms=_kms, key_id=key)
    assert pinned and not any("--key-id" in n for n in pinned.notes)


def test_signing_failure_fails_the_run(tmp_path):
    missing = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000"
    with pytest.raises(SinkError, match="signing the run manifest"):
        _collect([LocalSink(tmp_path)], signing={"kms_key_id": missing})
    assert not list(tmp_path.iterdir())  # nothing unsigned was delivered


# ------------------------------------------------------------------------- chain
def test_local_chain_starts_at_genesis_and_links_each_run(tmp_path):
    first, second = _chain(tmp_path, 2)
    assert first.previous is None
    assert second.previous == {"run_id": first.run_id, "sha256": first.sha256}
    assert LocalSink(tmp_path / "nope").latest_manifest(before="9") is None


def test_s3_chain_head_is_newest_complete_run():
    boto3.client("s3", region_name="us-east-1").create_bucket(Bucket=BUCKET)
    sink = S3Sink(BUCKET, prefix="grc")
    assert sink.latest_manifest(before="9") is None
    first = _collect([sink]).manifest
    second = _collect([sink], minutes=60 * 24).manifest  # next dt= partition
    assert second.previous == {"run_id": first.run_id, "sha256": first.sha256}
    # A newer partition holding only an incomplete run (no manifest.json) is skipped.
    boto3.client("s3", region_name="us-east-1").put_object(
        Bucket=BUCKET, Key="grc/dt=2026-09-30/20260930T000000Z-deadbeef/x.json", Body=b"{}"
    )
    assert sink.latest_manifest(before="20261231T000000Z")["run_id"] == second.run_id


def test_chain_lookup_failure_fails_closed(tmp_path, capsys):
    with pytest.raises(SinkError, match="s3:ListBucket and s3:GetObject"):
        run(_config(), now=NOW, sinks=[S3Sink("no-such-bucket")])
    blocker = tmp_path / "root-is-a-file"
    blocker.write_text("x")
    with pytest.raises(SinkError, match="could not read"):
        run(_config(), now=NOW, sinks=[LocalSink(blocker)])
    cfg = tmp_path / "c.yaml"
    cfg.write_text(
        "collectors: {include: [aws.iam_password_policy]}\nsinks: [{type: s3, bucket: gone}]\n"
    )
    assert cli.main(["collect", "--config", str(cfg)]) == 2
    assert "error: could not read the latest run manifest" in capsys.readouterr().err


def _plant(manifest: RunManifest, run_id: str) -> RunManifest:
    """A well-formed, correctly hashed copy of a real manifest under another run id."""
    forged = RunManifest.from_dict(manifest.to_dict())
    forged.run_id = run_id
    return forged.seal()


def test_poisoned_or_malformed_chain_head_is_skipped_local(tmp_path):
    sink = LocalSink(tmp_path)
    good = _collect([sink]).manifest
    future = tmp_path / "99991231T235959Z-poison00"
    shutil.copytree(tmp_path / good.run_id, future)
    (future / "manifest.json").write_text(json.dumps(_plant(good, future.name).to_dict()))
    for name, body in (
        ("20260920T060100Z-badjson0", "{"),
        ("20260920T060200Z-wrongid0", json.dumps({"run_id": "elsewhere", "sha256": "0" * 64})),
        ("20260920T060300Z-array000", "[]"),
    ):
        (tmp_path / name).mkdir()
        (tmp_path / name / "manifest.json").write_text(body)
    nxt = _collect([sink], minutes=5).manifest
    assert nxt.previous == {"run_id": good.run_id, "sha256": good.sha256}
    problems = " ".join(verify_run(tmp_path).problems)
    assert "malformed" in problems
    assert f"{nxt.run_id}: links to {good.run_id}" in problems  # skips the junk runs
    assert "99991231T235959Z-poison00: claims genesis" in problems


def test_poisoned_or_malformed_chain_head_is_skipped_s3(capsys):
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket=BUCKET)
    sink = S3Sink(BUCKET, prefix="grc")
    good = _collect([sink]).manifest
    for run_id, body in (
        (
            "99991231T235959Z-poison00",
            json.dumps(_plant(good, "99991231T235959Z-poison00").to_dict()),
        ),
        (
            "20260920T235959Z-poison01",
            json.dumps(_plant(good, "20260920T235959Z-poison01").to_dict()),
        ),
        ("20260920T060100Z-badjson0", "{"),
    ):
        partition = f"dt={run_id[:4]}-{run_id[4:6]}-{run_id[6:8]}"
        s3.put_object(Bucket=BUCKET, Key=f"grc/{partition}/{run_id}/manifest.json", Body=body)
    nxt = _collect([sink], minutes=5).manifest
    assert nxt.previous == {"run_id": good.run_id, "sha256": good.sha256}
    assert cli.main(["verify", f"s3://{BUCKET}/grc"]) == 1
    err = capsys.readouterr().err
    assert "20260920T060100Z-badjson0: manifest.json is unreadable" in err
    assert "99991231T235959Z-poison00: claims genesis" in err


# ------------------------------------------------------------------------ verify
def test_verify_an_intact_chain(tmp_path):
    _chain(tmp_path)
    result = verify_run(tmp_path)
    assert result and result.runs == 3 and result.chain_checked
    assert sum(n.endswith(": unsigned") for n in result.notes) == 3
    single = verify_run(latest_run_dir(tmp_path))
    assert single.runs == 1 and not single.chain_checked
    assert any("single run" in n for n in single.notes)


def test_verify_detects_a_deleted_middle_run(tmp_path):
    first, middle, last = _chain(tmp_path)
    shutil.rmtree(tmp_path / middle.run_id)
    assert verify_run(tmp_path).problems == [
        f"{last.run_id}: previous run {middle.run_id} is missing (deleted?)"
    ]


def test_verify_detects_a_renamed_or_reordered_run(tmp_path):
    first, middle, last = _chain(tmp_path)
    (tmp_path / middle.run_id).rename(tmp_path / "29990101T000000Z-zzzzzzzz")
    problems = " ".join(verify_run(tmp_path).problems)
    assert "directory name does not match run_id" in problems
    assert "reordered or forked" in problems


def test_verify_detects_a_fork(tmp_path):
    first, second = _chain(tmp_path, 2)
    _rewrite(tmp_path / second.run_id, lambda m: setattr(m, "previous", None))
    assert "claims genesis but earlier runs exist" in " ".join(verify_run(tmp_path).problems)
    # Two runs that both link to the same predecessor.
    _rewrite(
        tmp_path / second.run_id,
        lambda m: setattr(m, "previous", {"run_id": first.run_id, "sha256": first.sha256}),
    )
    third = _collect([LocalSink(tmp_path)], minutes=5).manifest
    _rewrite(tmp_path / third.run_id, lambda m: setattr(m, "previous", second.previous))
    assert "reordered or forked" in " ".join(verify_run(tmp_path).problems)


def test_verify_detects_a_rewritten_past_run_even_with_a_valid_hash(tmp_path):
    first, second, _ = _chain(tmp_path)
    _rewrite(tmp_path / first.run_id, lambda m: m.counts.update(pass_=99))
    problems = verify_run(tmp_path).problems
    assert problems == [
        f"{second.run_id}: previous run {first.run_id} was rewritten "
        "(its sha256 differs from the link)"
    ]


def test_verify_previous_link_edge_cases(tmp_path):
    first, second = _chain(tmp_path, 2)
    _rewrite(tmp_path / second.run_id, lambda m: setattr(m, "previous", {"run_id": 1}))
    assert "link is malformed" in " ".join(verify_run(tmp_path).problems)
    # The oldest run present links to a run that expired: a note, not a problem.
    shutil.rmtree(tmp_path / first.run_id)
    _rewrite(
        tmp_path / second.run_id,
        lambda m: setattr(m, "previous", {"run_id": first.run_id, "sha256": first.sha256}),
    )
    result = verify_run(tmp_path)
    assert result and any("expired by lifecycle" in n for n in result.notes)


def test_verify_unknown_schema_and_unreadable_run_in_a_chain(tmp_path):
    first, second, third = _chain(tmp_path)
    _rewrite(tmp_path / first.run_id, lambda m: setattr(m, "schema_version", "9.9"))
    (tmp_path / second.run_id / "manifest.json").write_text("{")
    problems = " ".join(verify_run(tmp_path).problems)
    assert "unknown schema_version '9.9'" in problems and "malformed" in problems
    assert "previous run" not in problems  # no link problem piled onto an unreadable run


def test_verify_signature_invalid_after_tampering_and_rehash(tmp_path):
    key = _signing_key()
    m = _collect([LocalSink(tmp_path)], signing={"kms_key_id": key}).manifest
    _rewrite(tmp_path / m.run_id, lambda m: m.counts.update(fail=0))  # keeps the old signature
    assert verify_run(tmp_path, kms=_kms).problems == [f"{m.run_id}: signature INVALID"]
    skipped = verify_run(tmp_path, kms=_kms, check_signature=False)
    assert skipped and any("--skip-signature" in n for n in skipped.notes)
    # Unrehashed tampering: the hash problem is reported, the signature is not checked at all.
    _rewrite(tmp_path / m.run_id, lambda m: m.counts.update(fail=7), reseal=False)
    assert verify_run(tmp_path, kms=lambda k: pytest.fail("no KMS call")).problems == [
        f"{m.run_id}: manifest hash does not match its contents"
    ]


def test_pinned_key_requires_signatures_and_rejects_other_keys(tmp_path):
    unsigned = tmp_path / "unsigned"
    _chain(unsigned, 1)
    key = _signing_key()
    assert verify_run(unsigned).notes[0].endswith("unsigned")
    assert "unsigned but a signing key was required" in verify_run(unsigned, key_id=key).problems[0]

    signed = tmp_path / "signed"
    _chain(signed, 1, signing={"kms_key_id": _signing_key()})  # a forger's own key
    assert verify_run(signed, kms=_kms)  # self-consistent without a pin
    assert "signature INVALID" in verify_run(signed, kms=_kms, key_id=key).problems[0]


class _FailingKms:
    def __init__(self, code):
        self.code = code

    def verify(self, **kwargs):
        raise ClientError({"Error": {"Code": self.code, "Message": "x"}}, "Verify")


def test_signature_errors_never_pass(tmp_path):
    m = _chain(tmp_path, 1, signing={"kms_key_id": _signing_key()})[0]
    real = verify_run(tmp_path, kms=lambda k: _FailingKms("KMSInvalidSignatureException"))
    assert real.problems == [f"{m.run_id}: signature INVALID"]
    denied = verify_run(tmp_path, kms=lambda k: _FailingKms("AccessDeniedException"))
    assert "signature could not be checked" in denied.problems[0] and denied.signatures == 0
    for bad in ({"value": "!!!", "key_id": "k", "algorithm": "a"}, {"value": "AA=="}, "sig"):
        _rewrite(tmp_path / m.run_id, lambda mm, bad=bad: setattr(mm, "signature", bad))
        assert verify_run(tmp_path, kms=_kms).problems == [f"{m.run_id}: signature is malformed"]


# ------------------------------------------------------------------------ legacy
def test_legacy_v1_manifest_verifies_and_can_precede_a_v2_run(tmp_path):
    body = _legacy_run(tmp_path, "20260101T000000Z-legacy01")
    stored = RunManifest.from_dict(body)
    assert stored.legacy and stored.verify() and stored.to_dict() == body  # byte-for-byte
    v2 = _collect([LocalSink(tmp_path)]).manifest
    assert v2.previous == {"run_id": body["run_id"], "sha256": body["sha256"]}
    result = verify_run(tmp_path)
    assert result, result.problems
    assert any("legacy schema 1.0" in n for n in result.notes)
    assert [d.name for d in run_dirs(tmp_path)] == [body["run_id"], v2.run_id]


def test_a_legacy_run_after_a_v2_run_is_a_downgrade(tmp_path):
    _chain(tmp_path, 1)
    _legacy_run(tmp_path, "29990101T000000Z-legacy02")
    assert "downgraded" in " ".join(verify_run(tmp_path).problems)


def test_pinned_key_rejects_a_store_with_no_signed_run(tmp_path):
    legacy = _legacy_run(tmp_path, "20260101T000000Z-legacy01")["run_id"]
    key = _signing_key()
    assert verify_run(tmp_path)  # notes only without a pin
    for target in (tmp_path, tmp_path / legacy):
        problems = verify_run(target, kms=_kms, key_id=key).problems
        assert problems == ["no signed schema 2.0 run; a pinned key requires at least one"]
    # Legacy runs before the first signed 2.0 run stay notes under the pin.
    _collect([LocalSink(tmp_path)], signing={"kms_key_id": key})
    assert verify_run(tmp_path, kms=_kms, key_id=key)


def test_unsigned_after_signed_is_a_stripped_signature(tmp_path, capsys):
    key = _signing_key()
    _, second = _chain(tmp_path / "stripped", 2, signing={"kms_key_id": key})
    _rewrite(tmp_path / "stripped" / second.run_id, lambda m: setattr(m, "signature", None))
    result = verify_run(tmp_path / "stripped", kms=_kms)
    assert result.unsigned == 1
    assert result.problems == [f"{second.run_id}: unsigned after signed runs (signature stripped?)"]
    # Unsigned runs before signing was turned on are allowed, and the OK line counts them.
    sink = LocalSink(tmp_path / "mixed")
    _collect([sink])
    _collect([sink], minutes=1, signing={"kms_key_id": key})
    assert cli.main(["verify", str(tmp_path / "mixed")]) == 0
    assert "1 signature(s), 1 unsigned, chain links" in capsys.readouterr().out


# --------------------------------------------------------------------------- CLI
def test_cli_verify_output_and_exit_codes(tmp_path, capsys):
    key = _signing_key()
    _chain(tmp_path, 2, signing={"kms_key_id": key})
    assert cli.main(["verify", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert (
        "OK: 2 run(s) verified (manifest and evidence hashes, 2 signature(s), chain links)" in out
    )
    assert "NOTE: signature checked against the key named in the manifest" in out
    assert cli.main(["verify", str(tmp_path), "--key-id", key]) == 0
    capsys.readouterr()
    assert cli.main(["verify", str(tmp_path), "--skip-signature"]) == 0
    out = capsys.readouterr().out
    assert "signature not checked (--skip-signature)" in out and "0 signature" not in out

    assert cli.main(["verify", str(tmp_path), "--key-id", _signing_key()]) == 1
    captured = capsys.readouterr()
    assert "TAMPERED/INCONSISTENT: " in captured.err and "signature INVALID" in captured.err
    assert "2 problem(s)" in captured.out
    assert cli.main(["verify", str(tmp_path / "missing")]) == 2


def test_cli_verify_s3_prefix(capsys):
    boto3.client("s3", region_name="us-east-1").create_bucket(Bucket=BUCKET)
    sink = S3Sink(BUCKET, prefix="grc")
    key = _signing_key()
    for i in range(2):
        _collect([sink], minutes=i, signing={"kms_key_id": key})
    assert cli.main(["verify", f"s3://{BUCKET}/grc", "--key-id", key]) == 0
    out = capsys.readouterr().out
    assert "OK: 2 run(s) verified" in out and "current version of each object only" in out

    s3 = boto3.client("s3", region_name="us-east-1")
    evidence_key = next(
        o["Key"]
        for o in s3.list_objects_v2(Bucket=BUCKET)["Contents"]
        if not o["Key"].endswith("manifest.json")
    )
    s3.put_object(Bucket=BUCKET, Key=evidence_key, Body=b'{"edited": true}')
    assert cli.main(["verify", f"s3://{BUCKET}/grc"]) == 1
    s3.put_object(Bucket=BUCKET, Key="grc/../escape.json", Body=b"{}")
    assert cli.main(["verify", f"s3://{BUCKET}/grc"]) == 2
    assert "unsafe or colliding S3 key" in capsys.readouterr().err
    assert cli.main(["verify", "s3://no-such-bucket/grc"]) == 2


@pytest.mark.parametrize(
    "keys", [["grc/dup/X.json", "grc/dup/x.json"], ["grc/a//b.json"], ["grc/a/./b.json"]]
)
def test_cli_verify_s3_rejects_colliding_or_empty_segment_keys(capsys, keys):
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket=BUCKET)
    _collect([S3Sink(BUCKET, prefix="grc")])
    for key in keys:
        s3.put_object(Bucket=BUCKET, Key=key, Body=b"{}")
    assert cli.main(["verify", f"s3://{BUCKET}/grc"]) == 2
    assert "unsafe or colliding S3 key" in capsys.readouterr().err


# ------------------------------------------------------------------------ Lambda
def test_lambda_summary_reports_signature_and_previous_run(monkeypatch, tmp_path):
    from grcevidence.lambda_handler import handler

    cfg = {
        "collectors": {"include": ["aws.iam_password_policy"]},
        "sinks": [{"type": "local", "path": str(tmp_path)}],
        "signing": {"kms_key_id": _signing_key()},
    }
    monkeypatch.setenv("GRC_CONFIG", json.dumps(cfg))
    first = handler({})
    second = handler({})
    assert first["signed"] and first["previous_run_id"] is None
    assert second["previous_run_id"] == first["run_id"]
