"""aws.config_rules tests.

The "no rules" case runs on moto (its DescribeConfigRules is right). moto 5.2.3 does not implement
DescribeComplianceByConfigRule or DescribeConfigRuleEvaluationStatus, so the other tests drive a
real boto3 Config client through botocore's Stubber.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import boto3
from botocore.stub import Stubber

from grcevidence.collectors.aws.config_rules import ConfigRules
from grcevidence.collectors.base import Context, Parameters
from grcevidence.models import Severity, Status
from tests.conftest import ACCOUNT, NOW

T1 = datetime(2026, 9, 19, 1, 0, tzinfo=UTC)
T2 = datetime(2026, 9, 19, 2, 0, tzinfo=UTC)


class _Session:
    def __init__(self, client: Any) -> None:
        self._client = client

    def client(self, *_: Any, **__: Any) -> Any:
        return self._client


def _rule(name: str, ident: str = "S3_BUCKET_VERSIONING_ENABLED") -> dict:
    return {
        "ConfigRuleName": name,
        "ConfigRuleArn": f"arn:aws:config:us-east-1:{ACCOUNT}:config-rule/{name}",
        "Source": {"Owner": "AWS", "SourceIdentifier": ident},
        "ConfigRuleState": "ACTIVE",
    }


def _run(rules: list, compliance: list, statuses: list, **params: Any):
    client = boto3.client("config", region_name="us-east-1")
    stub = Stubber(client)
    stub.add_response("describe_config_rules", {"ConfigRules": rules})
    stub.add_response("describe_compliance_by_config_rule", {"ComplianceByConfigRules": compliance})
    stub.add_response(
        "describe_config_rule_evaluation_status", {"ConfigRulesEvaluationStatus": statuses}
    )
    ctx = Context(ACCOUNT, "us-east-1", _Session(client), Parameters(**params), NOW)
    with stub:
        return ConfigRules().execute(ctx)


def test_rule_compliance_and_evaluation_failures():
    rules = [_rule(n) for n in ("ok", "bad", "nodata", "na", "stale", "missing")]
    compliance = [
        {"ConfigRuleName": "ok", "Compliance": {"ComplianceType": "COMPLIANT"}},
        {
            "ConfigRuleName": "bad",
            "Compliance": {
                "ComplianceType": "NON_COMPLIANT",
                "ComplianceContributorCount": {"CappedCount": 100, "CapExceeded": True},
            },
        },
        {"ConfigRuleName": "nodata", "Compliance": {"ComplianceType": "INSUFFICIENT_DATA"}},
        {"ConfigRuleName": "na", "Compliance": {"ComplianceType": "NOT_APPLICABLE"}},
        {"ConfigRuleName": "stale", "Compliance": {"ComplianceType": "COMPLIANT"}},
    ]
    statuses = [
        {"ConfigRuleName": "ok", "LastSuccessfulEvaluationTime": T2, "LastFailedEvaluationTime": T1},
        {"ConfigRuleName": "stale", "LastSuccessfulEvaluationTime": T1,
         "LastFailedEvaluationTime": T2, "LastErrorCode": "AccessDenied"},
    ]  # fmt: skip
    ev = _run(rules, compliance, statuses)
    assert ev.status == Status.FAIL
    res = {r["attributes"]["name"]: r for r in ev.data["resources"]}
    assert {n for n, r in res.items() if r["compliant"]} == {"ok", "na"}
    assert res["ok"]["type"] == "AWS::Config::ConfigRule"
    assert res["ok"]["attributes"]["last_successful_evaluation"] == "2026-09-19T02:00:00+00:00"
    assert res["missing"]["attributes"]["compliance"] == "INSUFFICIENT_DATA"
    assert res["bad"]["attributes"]["source_identifier"] == "S3_BUCKET_VERSIONING_ENABLED"
    got = {(f.resource, f.severity) for f in ev.findings}
    assert got == {
        ("bad", Severity.MEDIUM),
        ("nodata", Severity.LOW),
        ("missing", Severity.LOW),
        ("stale", Severity.MEDIUM),
    }
    assert any("100+ resource" in f.message for f in ev.findings)
    assert any("AccessDenied" in f.message for f in ev.findings)
    assert ev.data["compliance_counts"]["COMPLIANT"] == 2


def test_failed_first_evaluation_fails_and_clean_rule_passes():
    ev = _run(
        [_rule("ok")],
        [{"ConfigRuleName": "ok", "Compliance": {"ComplianceType": "COMPLIANT"}}],
        [{"ConfigRuleName": "ok", "LastFailedEvaluationTime": T1}],  # never succeeded
    )
    assert ev.status == Status.FAIL  # a failed first evaluation is not a pass
    ev = _run(
        [_rule("ok")],
        [{"ConfigRuleName": "ok", "Compliance": {"ComplianceType": "COMPLIANT"}}],
        [{"ConfigRuleName": "ok", "LastSuccessfulEvaluationTime": T1}],
    )
    assert ev.status == Status.PASS and ev.data["resources"][0]["compliant"] is True


def test_rule_cap_marks_incomplete():
    ev = _run([_rule("a"), _rule("b")], [], [], max_items_per_check=1)
    assert ev.status == Status.FAIL and ev.data["truncated"] is True
    assert len(ev.data["resources"]) == 1


def test_no_rules_is_not_applicable(make_ctx):
    ev = ConfigRules().execute(make_ctx())  # moto
    assert ev.status == Status.NOT_APPLICABLE
