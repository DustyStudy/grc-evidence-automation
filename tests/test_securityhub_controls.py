"""aws.securityhub_controls tests.

moto 5.2.3 has no GetEnabledStandards/DescribeStandards and ignores GetFindings filters, so every
test drives a real boto3 Security Hub client through botocore's Stubber (exact requests checked).
"""

from __future__ import annotations

from typing import Any

import boto3
from botocore.stub import ANY, Stubber

from grcevidence.collectors.aws.securityhub_controls import SecurityHubControls
from grcevidence.collectors.base import Context, Parameters
from grcevidence.models import Severity, Status
from tests.conftest import ACCOUNT, NOW

FSBP = "arn:aws:securityhub:us-east-1::standards/aws-foundational-security-best-practices/v/1.0.0"
CIS = "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0"


class _Session:
    def __init__(self, client: Any) -> None:
        self._client = client

    def client(self, *_: Any, **__: Any) -> Any:
        return self._client


def _stubbed() -> tuple[Any, Stubber]:
    client = boto3.client("securityhub", region_name="us-east-1")
    return client, Stubber(client)


def _ctx(client: Any, **params: Any) -> Context:
    return Context(ACCOUNT, "us-east-1", _Session(client), Parameters(**params), NOW)


def _finding(cid: str, status: str, res: str, label: str = "MEDIUM", std: str = FSBP) -> dict:
    return {
        "SchemaVersion": "2018-10-08",
        "Id": f"{cid}/{res}/{std}",
        "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
        "GeneratorId": cid,
        "AwsAccountId": ACCOUNT,
        "CreatedAt": "2026-09-01T00:00:00Z",
        "UpdatedAt": "2026-09-01T00:00:00Z",
        "Title": f"{cid} title",
        "Description": "d",
        "Severity": {"Label": label},
        "Resources": [{"Type": "AwsS3Bucket", "Id": res}],
        "Compliance": {
            "Status": status,
            "SecurityControlId": cid,
            "AssociatedStandards": [{"StandardsId": std.split(":", 5)[5]}],
        },
    }


def _enabled(stub: Stubber, subs: list[dict]) -> None:
    stub.add_response("describe_hub", {"HubArn": "arn:aws:securityhub:us-east-1:1:hub/default"})
    stub.add_response("get_enabled_standards", {"StandardsSubscriptions": subs})


def _sub(arn: str, status: str = "READY") -> dict:
    return {
        "StandardsSubscriptionArn": f"{arn}/subscription",
        "StandardsArn": arn,
        "StandardsInput": {},
        "StandardsStatus": status,
    }


def test_controls_grouped_and_failed_controls_raise_findings():
    client, stub = _stubbed()
    _enabled(stub, [_sub(FSBP), _sub(CIS, "INCOMPLETE")])
    stub.add_response(
        "describe_standards",
        {"Standards": [{"StandardsArn": FSBP, "Name": "AWS FSBP"}, {"StandardsArn": CIS}]},
    )
    findings = [
        _finding("S3.1", "FAILED", "b1", "HIGH"),
        _finding("S3.1", "PASSED", "b2", "HIGH"),
        _finding("S3.1", "FAILED", "b1", "CRITICAL", CIS),  # same resource, other standard
        _finding("IAM.1", "PASSED", "u1", "LOW"),
        _finding("EC2.2", "WARNING", "sg1", "INFORMATIONAL"),
        {**_finding("X", "PASSED", "z"), "Compliance": {"Status": "PASSED"}},  # no control id
    ]
    stub.add_response("get_findings", {"Findings": findings}, {"Filters": ANY})
    with stub:
        ev = SecurityHubControls().execute(_ctx(client))
    assert ev.status == Status.FAIL
    by_id = {r["id"]: r for r in ev.data["resources"]}
    s3 = by_id["S3.1"]
    assert s3["type"] == "AWS::SecurityHub::SecurityControl" and s3["compliant"] is False
    assert s3["attributes"]["failed_resources"] == 1 and s3["attributes"]["passed_resources"] == 1
    assert s3["attributes"]["severity"] == "CRITICAL" and len(s3["attributes"]["standards"]) == 2
    assert by_id["IAM.1"]["compliant"] is True
    assert by_id["EC2.2"]["attributes"]["compliance_status"] == "UNKNOWN"
    assert by_id[f"{CIS}/subscription"]["compliant"] is False
    assert by_id[f"{FSBP}/subscription"]["attributes"]["name"] == "AWS FSBP"
    sev = {f.resource: f.severity for f in ev.findings}
    assert sev == {"S3.1": Severity.CRITICAL, "EC2.2": Severity.LOW, CIS: Severity.MEDIUM}
    assert ev.data["control_status_counts"] == {"FAILED": 1, "PASSED": 1, "UNKNOWN": 1}
    assert ev.data["findings_examined"] == 6


def test_findings_query_is_scoped_to_account_region_and_active_unsuppressed():
    client, stub = _stubbed()
    _enabled(stub, [_sub(FSBP)])
    stub.add_response("describe_standards", {"Standards": []})
    expected = {
        "AwsAccountId": [{"Value": ACCOUNT, "Comparison": "EQUALS"}],
        "Region": [{"Value": "us-east-1", "Comparison": "EQUALS"}],
        "ProductName": [{"Value": "Security Hub", "Comparison": "EQUALS"}],
        "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
        "WorkflowStatus": [{"Value": "SUPPRESSED", "Comparison": "NOT_EQUALS"}],
        "ComplianceStatus": [
            {"Value": v, "Comparison": "EQUALS"}
            for v in ("FAILED", "PASSED", "WARNING", "NOT_AVAILABLE")
        ],
    }
    stub.add_response(
        "get_findings", {"Findings": [_finding("IAM.1", "PASSED", "u1")]}, {"Filters": expected}
    )
    with stub:
        ev = SecurityHubControls().execute(_ctx(client))
    stub.assert_no_pending_responses()
    assert ev.status == Status.PASS


def test_findings_cap_marks_incomplete():
    client, stub = _stubbed()
    _enabled(stub, [_sub(FSBP)])
    stub.add_response("describe_standards", {"Standards": []})
    stub.add_response(
        "get_findings",
        {"Findings": [_finding("IAM.1", "PASSED", f"u{i}") for i in range(41)]},
        {"Filters": ANY},
    )
    with stub:
        ev = SecurityHubControls().execute(_ctx(client, max_items_per_check=2))
    assert ev.status == Status.ERROR and ev.data["truncated"] is True
    assert ev.data["findings_examined"] == 40  # findings cap is 20x the resource cap


def test_not_enabled_is_not_applicable():
    for code in ("InvalidAccessException", "ResourceNotFoundException"):
        client, stub = _stubbed()
        stub.add_client_error("describe_hub", code)
        with stub:
            ev = SecurityHubControls().execute(_ctx(client))
        assert ev.status == Status.NOT_APPLICABLE and "not enabled" in ev.summary


def test_access_denied_is_error_not_pass():
    client, stub = _stubbed()
    stub.add_client_error("describe_hub", "AccessDeniedException")
    with stub:
        assert SecurityHubControls().execute(_ctx(client)).status == Status.ERROR


def test_no_enabled_standards_is_not_applicable():
    client, stub = _stubbed()
    _enabled(stub, [])
    with stub:
        ev = SecurityHubControls().execute(_ctx(client))
    assert ev.status == Status.NOT_APPLICABLE and "no enabled standards" in ev.summary


def test_no_control_findings_yet_is_not_applicable():
    client, stub = _stubbed()
    _enabled(stub, [_sub(FSBP)])
    stub.add_response("describe_standards", {"Standards": []})
    stub.add_response("get_findings", {"Findings": []}, {"Filters": ANY})
    with stub:
        ev = SecurityHubControls().execute(_ctx(client))
    assert ev.status == Status.NOT_APPLICABLE
    assert ev.data["resources"][0]["type"] == "AWS::SecurityHub::Standard"
