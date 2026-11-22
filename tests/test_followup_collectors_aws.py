"""False-PASS gaps closed in the AWS collectors. Stub clients are used where moto cannot
produce the state (denied reads, failing flow-log delivery, split CIDR ranges)."""

from __future__ import annotations

import json
import socket
from types import SimpleNamespace as NS

import pytest
from botocore.exceptions import ClientError

from grcevidence.collectors.aws.monitoring import NetworkExposure, VpcFlowLogs
from grcevidence.collectors.aws.policy import admin_statements
from grcevidence.collectors.aws.privileged import IamPrivilegedAccess
from grcevidence.collectors.aws.storage import S3Security
from grcevidence.models import Severity, Status


def _paged(**pages):
    """A client whose paginators each return one canned page, keyed by operation name."""
    return NS(get_paginator=lambda op: NS(paginate=lambda **_kw: [pages[op]]))


def _with_client(make_ctx, monkeypatch, client):
    ctx = make_ctx()
    monkeypatch.setattr(ctx, "client", client)
    return ctx


# -------------------------------------------------------------------------- S3
class _CleanS3:
    """Every setting compliant; ``versioning_error`` makes GetBucketVersioning fail."""

    def __init__(self, names=("b",), versioning_error=None):
        self.names, self.versioning_error = names, versioning_error

    def list_buckets(self):
        return {"Buckets": [{"Name": n} for n in self.names]}

    def get_public_access_block(self, Bucket):  # noqa: N803 - boto3 keyword
        keys = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
        return {"PublicAccessBlockConfiguration": dict.fromkeys(keys, True)}

    def get_bucket_encryption(self, Bucket):  # noqa: N803
        return {"ServerSideEncryptionConfiguration": {"Rules": [{}]}}

    def get_bucket_policy_status(self, Bucket):  # noqa: N803
        return {"PolicyStatus": {"IsPublic": False}}

    def get_bucket_versioning(self, Bucket):  # noqa: N803
        if self.versioning_error:
            raise ClientError({"Error": {"Code": self.versioning_error}}, "GetBucketVersioning")
        return {"Status": "Enabled"}


def test_s3_clean_bucket_passes(make_ctx, monkeypatch):
    ev = S3Security().execute(_with_client(make_ctx, monkeypatch, lambda *_a, **_k: _CleanS3()))
    assert ev.status == Status.PASS and ev.findings == []


def test_s3_denied_versioning_read_is_an_error_not_a_pass(make_ctx, monkeypatch):
    s3 = _CleanS3(versioning_error="AccessDenied")
    ev = S3Security().execute(_with_client(make_ctx, monkeypatch, lambda *_a, **_k: s3))
    assert ev.status == Status.ERROR
    assert [(f.resource, f.message) for f in ev.findings] == [
        ("b", "Could not read versioning: AccessDenied")
    ]
    (res,) = ev.data["resources"]
    assert res["compliant"] is False and res["attributes"]["versioning"] is None


def test_s3_fips_listing_does_not_pass_with_non_us_regions_unexamined(make_ctx, monkeypatch):
    """Cloud Control ListResources is region-scoped, so a bucket in eu-west-1 is never listed
    by the US queries: clean US buckets alone must not produce PASS."""
    regions = ["ap-south-1", "eu-west-1", "us-east-1"]

    def client(svc, region=None):
        if svc == "ec2":
            return NS(describe_regions=lambda: {"Regions": [{"RegionName": r} for r in regions]})
        if svc == "cloudcontrol":
            assert region == "us-east-1"
            page = {"ResourceDescriptions": [{"Identifier": "b"}]}
            return NS(
                meta=NS(endpoint_url="https://cloudcontrolapi-fips.us-east-1.amazonaws.com"),
                get_paginator=lambda _op: NS(paginate=lambda **_kw: [page]),
            )
        return _CleanS3()

    ctx = _with_client(make_ctx, monkeypatch, client)
    ctx.use_fips_endpoint = True
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_a, **_k: [("ok",)])
    ev = S3Security().execute(ctx)
    assert ev.status == Status.FAIL and ev.data["buckets_examined"] == 1
    (f,) = ev.findings
    assert f.resource == "regions_out_of_scope" and f.severity == Severity.MEDIUM
    assert f.message.endswith(": ap-south-1, eu-west-1")
    assert ev.data["regions_out_of_scope"] == ["ap-south-1", "eu-west-1"]


# ----------------------------------------------------------------- flow logs
@pytest.mark.parametrize(
    "flow_log,covered",
    [
        ({"FlowLogStatus": "ACTIVE", "DeliverLogsStatus": "SUCCESS", "TrafficType": "ALL"}, True),
        ({"DeliverLogsStatus": "SUCCESS", "TrafficType": "ACCEPT"}, True),
        ({"FlowLogStatus": "ACTIVE", "DeliverLogsStatus": "FAILED", "TrafficType": "ALL"}, False),
        ({"FlowLogStatus": "ACTIVE", "TrafficType": "ALL"}, False),  # delivery status unknown
        (
            {"FlowLogStatus": "ACTIVE", "DeliverLogsStatus": "SUCCESS", "TrafficType": "REJECT"},
            False,
        ),
        (
            {"FlowLogStatus": "INACTIVE", "DeliverLogsStatus": "SUCCESS", "TrafficType": "ALL"},
            False,
        ),
    ],
)
def test_vpc_flow_log_must_be_active_delivering_and_not_reject_only(
    make_ctx, monkeypatch, flow_log, covered
):
    ec2 = _paged(
        describe_vpcs={"Vpcs": [{"VpcId": "vpc-1"}]},
        describe_flow_logs={"FlowLogs": [{"ResourceId": "vpc-1", **flow_log}]},
    )
    ev = VpcFlowLogs().execute(_with_client(make_ctx, monkeypatch, lambda *_a, **_k: ec2))
    assert ev.status == (Status.PASS if covered else Status.FAIL)
    assert ev.data["resources"][0]["compliant"] is covered
    assert [f.resource for f in ev.findings] == ([] if covered else ["vpc-1"])


# ----------------------------------------------------------- security groups
def _perm(proto, cidrs, lo=22, hi=22):
    perm = {
        "IpProtocol": proto,
        "IpRanges": [{"CidrIp": c} for c in cidrs if ":" not in c],
        "Ipv6Ranges": [{"CidrIpv6": c} for c in cidrs if ":" in c],
    }
    return perm if proto == "-1" else {**perm, "FromPort": lo, "ToPort": hi}


def _exposure(make_ctx, monkeypatch, *perms):
    group = {"GroupId": "sg-1", "GroupName": "g", "IpPermissions": list(perms)}
    ec2 = _paged(describe_security_groups={"SecurityGroups": [group]})
    return NetworkExposure().execute(_with_client(make_ctx, monkeypatch, lambda *_a, **_k: ec2))


V4_HALVES = ["0.0.0.0/1", "128.0.0.0/1"]


@pytest.mark.parametrize(
    "perms",
    [
        [_perm("tcp", V4_HALVES)],
        [_perm("6", ["::/1", "8000::/1"])],
        [_perm("tcp", ["0.0.0.0/2", "64.0.0.0/2", "128.0.0.0/1"])],
        [_perm("tcp", ["0.0.0.0/1"]), _perm("tcp", ["128.0.0.0/1"], lo=20, hi=30)],  # two rules
        [_perm("-1", ["0.0.0.0/1"]), _perm("tcp", ["128.0.0.0/1"])],  # all-protocols half
        [_perm("tcp", ["1.2.3.4/0"])],  # host bits set, still every address
        [_perm("tcp", ["0::/0"])],
    ],
)
def test_split_or_unusual_ranges_covering_the_internet_are_open(make_ctx, monkeypatch, perms):
    ev = _exposure(make_ctx, monkeypatch, *perms)
    assert ev.status == Status.FAIL
    assert [(f.message, f.severity) for f in ev.findings] == [
        ("Port 22/tcp open to the internet", Severity.HIGH)
    ]
    assert ev.data["resources"][0]["attributes"] == {
        "open_to_internet_ports": [22],
        "all_traffic": False,
    }


def test_all_protocols_from_split_ranges_is_critical(make_ctx, monkeypatch):
    ev = _exposure(make_ctx, monkeypatch, _perm("-1", V4_HALVES))
    assert [(f.message, f.severity) for f in ev.findings] == [
        ("Allows ALL traffic from the internet", Severity.CRITICAL)
    ]
    assert ev.data["resources"][0]["attributes"]["all_traffic"] is True


@pytest.mark.parametrize(
    "perms",
    [
        [_perm("tcp", ["0.0.0.0/1"])],  # half the internet is not "the internet" for this check
        [_perm("tcp", ["0.0.0.0/1", "8000::/1"])],  # halves of different families
        [_perm("tcp", V4_HALVES, lo=443, hi=443)],
        [_perm("tcp", ["0.0.0.0/1"]), _perm("tcp", ["128.0.0.0/1"], lo=443, hi=443)],
        [_perm("udp", V4_HALVES)],
    ],
)
def test_ranges_not_covering_the_internet_on_a_sensitive_port_pass(make_ctx, monkeypatch, perms):
    ev = _exposure(make_ctx, monkeypatch, *perms)
    assert ev.status == Status.PASS and ev.findings == []


def test_malformed_cidr_is_an_error_not_a_pass(make_ctx, monkeypatch):
    assert _exposure(make_ctx, monkeypatch, _perm("tcp", ["not-a-cidr"])).status == Status.ERROR


# ------------------------------------------------------- privilege escalation
def _doc(**stmt):
    return {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", **stmt}]}


@pytest.mark.parametrize(
    "action",
    [
        "iam:AttachUserPolicy",
        "iam:PutUserPolicy",
        "iam:CreatePolicyVersion",
        "iam:SetDefaultPolicyVersion",
        "iam:AddUserToGroup",
        "iam:CreateAccessKey",
        "iam:UpdateAssumeRolePolicy",
        "iam:Attach*",
        "iam:Put*",
        "iam:Put*Policy",
        "IAM:ATTACHROLEPOLICY",
        "iam:*Policy*",
        "iam:Create?ccessKey",
    ],
)
def test_privilege_escalation_actions_are_admin_equivalent(action):
    assert admin_statements(_doc(Action=action, Resource="*"))
    assert admin_statements(_doc(Action=["s3:GetObject", action], Resource="arn:aws:iam::*:*"))
    assert not admin_statements(_doc(Action=action, Resource="arn:aws:iam::*:user/x"))


@pytest.mark.parametrize(
    "action", ["iam:PassRole", "iam:Get*", "iam:List*", "iam:CreateUser", "s3:Put*", "sts:*"]
)
def test_other_actions_are_not_admin_equivalent(action):
    assert not admin_statements(_doc(Action=action, Resource="*"))


@pytest.mark.parametrize(
    "not_action,admin",
    [
        ("iam:AttachUserPolicy", True),  # every other escalation action is still granted
        (["iam:Attach*", "iam:Put*"], True),
        (["iam:A*", "iam:P*", "iam:C*", "iam:S*", "iam:U*"], False),
    ],
)
def test_not_action_must_exclude_every_escalation_action(not_action, admin):
    doc = _doc(NotAction=not_action, Resource="arn:aws:iam::*:*")
    assert bool(admin_statements(doc)) is admin


def test_user_with_escalation_action_is_recorded_as_privileged(make_ctx, session):
    iam = session.client("iam")
    for name, action in (("esc", "iam:AttachUserPolicy"), ("plain", "iam:PassRole")):
        iam.create_user(UserName=name)
        iam.put_user_policy(
            UserName=name,
            PolicyName="p",
            PolicyDocument=json.dumps(_doc(Action=action, Resource="*")),
        )
    ev = IamPrivilegedAccess().execute(make_ctx())
    assert ev.status == Status.FAIL
    assert ev.data["admin_users"] == ["esc"] and [f.resource for f in ev.findings] == ["esc"]
    assert any("trust policies" in note for note in ev.data["limitations"])
