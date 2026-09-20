from __future__ import annotations

from types import SimpleNamespace as NS

import pytest

from grcevidence import catalog
from grcevidence.collectors.base import (
    Collector,
    Context,
    Parameters,
    Result,
    load_all,
    register,
    select,
)
from grcevidence.collectors.gcp.gcp import GcpFirewallExposure, GcsBuckets
from grcevidence.models import Evidence, Finding, RunManifest, Severity, Status

# ------------------------------------------------------------------------ models


def _ev(**kw):
    base = dict(
        collector="aws.x",
        provider="aws",
        title="t",
        account="111111111111",
        region="us-east-1",
        collected_at="2026-09-20T06:00:00+00:00",
        status=Status.PASS,
        summary="ok",
        findings=[Finding("r", "m", Severity.HIGH)],
        data={"n": 1},
        controls={"soc2": ["CC6.1"]},
    )
    base.update(kw)
    return Evidence(**base).seal()


def test_evidence_hash_detects_any_change():
    ev = _ev()
    assert ev.verify()
    for mutate in (
        lambda e: setattr(e, "status", Status.FAIL),
        lambda e: e.data.update(n=2),
        lambda e: e.findings.append(Finding("x", "y")),
        lambda e: setattr(e, "summary", "changed"),
    ):
        tampered = Evidence.from_dict(ev.to_dict())
        mutate(tampered)
        assert not tampered.verify()


def test_evidence_roundtrip_and_filename():
    ev = _ev(region="global", account="acct/1")
    again = Evidence.from_dict(ev.to_dict())
    assert again == ev and again.verify()
    assert "/" not in ev.filename and ev.filename.endswith(".json")


def test_manifest_seal_verify():
    m = RunManifest("r1", "s", "f", "0.1.0", ["a"], {"pass": 1}, [{"id": "x"}]).seal()
    assert m.verify()
    m.counts["pass"] = 5
    assert not m.verify()


# ----------------------------------------------------------------------- catalog


def test_crosswalk_is_consistent_with_registered_collectors():
    assert catalog.validate_mapping(list(load_all())) == []


def test_validate_mapping_reports_problems(monkeypatch):
    monkeypatch.setattr(
        catalog, "collector_map", lambda: {"aws.ghost": {"soc2": ["CC99.9"], "nope": ["X"]}}
    )
    problems = catalog.validate_mapping(["aws.real"])
    text = " ".join(problems)
    assert (
        "CC99.9" in text
        and "unknown framework" in text
        and "aws.real" in text
        and "aws.ghost" in text
    )


def test_coverage_marks_gaps_and_organizational():
    soc2 = {r.control: r for r in catalog.coverage("soc2")}
    assert soc2["CC6.6"].automated and "aws.network_exposure" in soc2["CC6.6"].collectors
    assert not soc2["CC1.1"].automated and soc2["CC1.1"].type == "organizational"
    assert not soc2["A1.1"].automated and soc2["A1.1"].type == "technical"  # a genuine gap
    with pytest.raises(ValueError):
        catalog.coverage("hipaa")


def test_every_framework_has_some_automated_coverage_and_markdown_renders():
    for fw in catalog.FRAMEWORKS:
        assert any(r.automated for r in catalog.coverage(fw))
    md = catalog.coverage_markdown()
    assert "technical (gap)" in md and "SOC 2" in md and "NIST" in md


def test_committed_coverage_doc_is_current():
    from pathlib import Path

    doc = Path(__file__).resolve().parents[1] / "docs" / "coverage.md"
    assert doc.read_text(encoding="utf-8").strip() == catalog.coverage_markdown().strip(), (
        "regenerate with: grc-evidence coverage --format markdown > docs/coverage.md"
    )


# --------------------------------------------------------------------- registry


def test_registry_lists_all_collectors_and_select_filters():
    ids = set(load_all())
    assert len(ids) >= 15 and {"aws.iam_mfa", "gcp.storage_buckets"} <= ids
    assert {c.id for c in select(provider="gcp")} == {
        "gcp.storage_buckets",
        "gcp.firewall_exposure",
    }
    assert [c.id for c in select(include=["aws.cloudtrail"])] == ["aws.cloudtrail"]
    assert "aws.cloudtrail" not in {c.id for c in select(exclude=["aws.cloudtrail"])}
    with pytest.raises(ValueError, match="unknown collector"):
        select(include=["aws.nope"])


def test_duplicate_collector_id_rejected():
    class Dup(Collector):
        id = "aws.iam_mfa"
        title = "dup"

    with pytest.raises(ValueError, match="duplicate"):
        register(Dup)


def test_every_collector_declares_permissions_title_and_valid_scope():
    for cid, cls in load_all().items():
        assert cls.title and cls.scope in {"global", "regional"}, cid
        assert cls.permissions, cid


def test_parameters_reject_unknown_keys_and_coerce_ports():
    with pytest.raises(ValueError, match="unknown parameter"):
        Parameters.from_dict({"max_key_age": 1})
    assert Parameters.from_dict({"sensitive_ports": ["22", 80]}).sensitive_ports == (22, 80)


def test_execute_wraps_arbitrary_expected_failures():
    class Broken(Collector):
        id = "aws.broken_test"
        title = "b"

        def collect(self, ctx):
            raise ValueError("bad config")

    ev = Broken().execute(Context("1", "us-east-1"))
    assert ev.status == Status.ERROR and "ValueError" in ev.summary


def test_result_status_override_respected():
    class Info(Collector):
        id = "aws.info_test"
        title = "i"

        def collect(self, ctx):
            return Result("just info", status=Status.INFO)

    assert Info().execute(Context("1", "us-east-1")).status == Status.INFO


# --------------------------------------------------------------------------- GCP


class FakeStorage:
    def __init__(self, buckets):
        self._b = buckets

    def list_buckets(self):
        return iter(self._b)


class FakeFirewalls:
    def __init__(self, rules):
        self._r = rules

    def list(self, project):
        assert project == "proj-1"
        return iter(self._r)


class FakeClients:
    def __init__(self, buckets=(), rules=()):
        self._s, self._f = FakeStorage(list(buckets)), FakeFirewalls(list(rules))

    def storage(self):
        return self._s

    def firewalls(self):
        return self._f


def _bucket(name, ubla, pap):
    return NS(
        name=name,
        iam_configuration=NS(
            uniform_bucket_level_access_enabled=ubla, public_access_prevention=pap
        ),
    )


def _ctx(clients):
    return Context(
        "proj-1", "global", None, Parameters(), gcp_project="proj-1", gcp_clients=clients
    )


def test_gcs_buckets_findings():
    clients = FakeClients(
        [
            _bucket("good", True, "enforced"),
            _bucket("legacy", False, "inherited"),
            _bucket("noub", True, None),
        ]
    )
    ev = GcsBuckets().execute(_ctx(clients))
    assert ev.status == Status.FAIL and ev.provider == "gcp" and ev.region == "global"
    flagged = sorted({f.resource for f in ev.findings})
    assert flagged == ["legacy", "noub"] and ev.data["buckets_examined"] == 3
    assert ev.controls["soc2"] == ["CC6.1", "CC6.7", "C1.1"]


def test_gcs_all_good_passes():
    assert (
        GcsBuckets().execute(_ctx(FakeClients([_bucket("g", True, "enforced")]))).status
        == Status.PASS
    )


def _rule(name, ranges, allowed, direction="INGRESS", disabled=False):
    return NS(
        name=name, source_ranges=ranges, allowed=allowed, direction=direction, disabled=disabled
    )


def test_gcp_firewall_findings():
    rules = [
        _rule("ssh-open", ["0.0.0.0/0"], [NS(I_p_protocol="tcp", ports=["22"])]),
        _rule("range-open", ["0.0.0.0/0"], [NS(I_p_protocol="tcp", ports=["3000-4000"])]),
        _rule("all-open", ["0.0.0.0/0"], [NS(I_p_protocol="all", ports=[])]),
        _rule("tcp-any-port", ["0.0.0.0/0"], [NS(ip_protocol="tcp", ports=[])]),
        _rule("web", ["0.0.0.0/0"], [NS(I_p_protocol="tcp", ports=["443"])]),
        _rule("internal", ["10.0.0.0/8"], [NS(I_p_protocol="tcp", ports=["22"])]),
        _rule("egress", ["0.0.0.0/0"], [NS(I_p_protocol="tcp", ports=["22"])], direction="EGRESS"),
        _rule("disabled", ["0.0.0.0/0"], [NS(I_p_protocol="tcp", ports=["22"])], disabled=True),
    ]
    ev = GcpFirewallExposure().execute(_ctx(FakeClients(rules=rules)))
    assert sorted({f.resource for f in ev.findings}) == [
        "all-open",
        "range-open",
        "ssh-open",
        "tcp-any-port",
    ]
    assert ev.status == Status.FAIL


def test_gcp_without_library_or_credentials_is_error_not_pass():
    # No injected clients and google libs absent/unauthenticated: must surface as ERROR.
    ev = GcsBuckets().execute(Context("proj-1", "global", None, Parameters(), gcp_project="proj-1"))
    assert ev.status == Status.ERROR


def test_committed_collector_reference_is_current():
    from pathlib import Path

    doc = Path(__file__).resolve().parents[1] / "docs" / "collectors.md"
    assert doc.read_text(encoding="utf-8").strip() == catalog.collectors_markdown().strip(), (
        "regenerate with: grc-evidence collectors --format markdown > docs/collectors.md"
    )


def test_example_config_parses_and_uses_only_known_collectors():
    from pathlib import Path

    from grcevidence.runner import Config

    cfg = Config.from_file(Path(__file__).resolve().parents[1] / "examples" / "config.example.yaml")
    assert len(cfg.accounts) == 2 and {s["type"] for s in cfg.sinks} == {"local", "s3", "http"}
    assert not set(cfg.exclude) - set(load_all())
