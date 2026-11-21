"""aws.iam_privileged_access against moto's IAM (GetAccountAuthorizationDetails, GetPolicy and
GetPolicyVersion are all modelled), except the listing-without-document cases, which use a small
stub client. The policy-analysis edge cases live in test_policy_analysis."""

from __future__ import annotations

import json
from types import SimpleNamespace

from grcevidence.collectors.aws.policy import CONDITIONAL_NOTE
from grcevidence.collectors.aws.privileged import IamPrivilegedAccess
from grcevidence.models import Status

ADMIN_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
TRUST = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)


def _policy(action, condition=None):
    stmt = {"Effect": "Allow", "Action": action, "Resource": "*"}
    if condition:
        stmt["Condition"] = condition
    return json.dumps({"Version": "2012-10-17", "Statement": [stmt]})


def _by_id(ev):
    return {r["id"]: r for r in ev.data["resources"]}


def test_privileged_access_finds_admin_equivalent_principals(make_ctx, session, monkeypatch):
    monkeypatch.setenv("MOTO_IAM_LOAD_MANAGED_POLICIES", "true")  # AdministratorAccess must exist
    iam = session.client("iam")
    iam_full = iam.create_policy(PolicyName="iam-full", PolicyDocument=_policy("iam:*"))
    iam_full_arn = iam_full["Policy"]["Arn"]
    iam.create_policy(PolicyName="s3-only", PolicyDocument=_policy("s3:*"))

    iam.create_user(UserName="erin")  # direct AWS managed attach -> finding
    iam.attach_user_policy(UserName="erin", PolicyArn=ADMIN_ARN)
    iam.create_user(UserName="ivan")  # inline admin -> finding
    iam.put_user_policy(UserName="ivan", PolicyName="all", PolicyDocument=_policy("*"))
    iam.create_user(UserName="gina")  # admin only through her group -> listed, compliant
    iam.create_group(GroupName="admins")
    iam.attach_group_policy(GroupName="admins", PolicyArn=ADMIN_ARN)
    iam.add_user_to_group(GroupName="admins", UserName="gina")
    iam.create_user(UserName="sam")  # s3 only -> not admin
    iam.attach_user_policy(
        UserName="sam", PolicyArn=f"arn:aws:iam::{iam_full_arn.split(':')[4]}:policy/s3-only"
    )

    iam.create_role(RoleName="ops", AssumeRolePolicyDocument=TRUST)
    iam.attach_role_policy(RoleName="ops", PolicyArn=iam_full_arn)
    iam.create_role(
        RoleName="AWSServiceRoleForX", Path="/aws-service-role/x/", AssumeRolePolicyDocument=TRUST
    )
    iam.put_role_policy(
        RoleName="AWSServiceRoleForX",
        PolicyName="mfa-admin",
        PolicyDocument=_policy("*", {"Bool": {"aws:MultiFactorAuthPresent": "true"}}),
    )

    ev = IamPrivilegedAccess().execute(make_ctx())

    assert ev.status == Status.FAIL
    assert sorted(f.resource for f in ev.findings) == ["erin", "ivan"]
    assert ev.data["admin_users"] == ["erin", "gina", "ivan"]
    assert ev.data["admin_groups"] == ["admins"]
    assert ev.data["admin_roles"] == ["AWSServiceRoleForX", "ops"]
    assert ev.data["admin_policies"] == [iam_full_arn]
    assert ev.data["limitations"]
    res = _by_id(ev)
    assert "sam" not in res
    assert res["erin"]["attributes"]["via"] == [f"managed:{ADMIN_ARN}"]
    assert res["erin"]["compliant"] is False
    assert res["ivan"]["attributes"] == {
        "via": ["inline:all"],
        "policies": ["all"],
        "has_condition": False,
    }
    assert res["gina"] == {
        "id": "gina",
        "type": "AWS::IAM::User",
        "compliant": True,
        "attributes": {"via": ["group:admins"], "policies": [], "has_condition": False},
    }
    assert res["admins"]["type"] == "AWS::IAM::Group"
    assert res["ops"]["attributes"]["service_linked"] is False
    slr = res["AWSServiceRoleForX"]
    assert slr["type"] == "AWS::IAM::Role" and slr["compliant"] is True
    assert slr["attributes"]["service_linked"] is True
    assert slr["attributes"]["has_condition"] is True


def test_privileged_access_clean_account_passes(make_ctx):
    ev = IamPrivilegedAccess().execute(make_ctx())
    assert ev.status == Status.PASS
    assert ev.data["resources"] == [] and ev.data["admin_users"] == []


def test_privileged_access_respects_the_cap(make_ctx, session):
    iam = session.client("iam")
    for name in ("a", "b", "c"):
        iam.create_user(UserName=name)
        iam.put_user_policy(UserName=name, PolicyName="all", PolicyDocument=_policy("*"))
    ev = IamPrivilegedAccess().execute(make_ctx(max_items_per_check=2))
    assert ev.data["truncated"] is True
    assert ev.data["principals_examined"] == 2
    assert len(ev.data["resources"]) == 2


def test_privileged_access_notes_a_conditional_grant(make_ctx, session):
    iam = session.client("iam")
    iam.create_user(UserName="cara")
    mfa = {"Bool": {"aws:MultiFactorAuthPresent": "true"}}
    iam.put_user_policy(UserName="cara", PolicyName="mfa", PolicyDocument=_policy("*", mfa))
    ev = IamPrivilegedAccess().execute(make_ctx())
    assert [f.message.endswith(CONDITIONAL_NOTE) for f in ev.findings] == [True]
    assert _by_id(ev)["cara"]["attributes"]["has_condition"] is True


class _ListingWithoutDocument:
    """Stub IAM: moto's GetAccountAuthorizationDetails always embeds the default document, so
    the listing that omits it (and the fetch fallback) is faked here."""

    ARN = "arn:aws:iam::123456789012:policy/local"

    def __init__(self, fetched):
        self.fetched, self.calls = fetched, []

    def get_paginator(self, _op):
        return self

    def paginate(self, **_kw):
        user = {
            "UserName": "u",
            "AttachedManagedPolicies": [{"PolicyArn": self.ARN, "PolicyName": "local"}],
        }
        version = {"VersionId": "v2", "IsDefaultVersion": True}  # no "Document"
        yield {
            "UserDetailList": [user],
            "Policies": [{"Arn": self.ARN, "PolicyVersionList": [version]}],
        }

    def get_policy(self, PolicyArn):  # noqa: N803 - boto3 keyword
        self.calls.append(PolicyArn)
        return {"Policy": {"DefaultVersionId": "v2"}}

    def get_policy_version(self, PolicyArn, VersionId):  # noqa: N803
        return {"PolicyVersion": {"VersionId": VersionId, **self.fetched}}


def _ctx_with(make_ctx, client):
    ctx = make_ctx()
    ctx.session = SimpleNamespace(client=lambda *_a, **_kw: client)
    return ctx


def test_privileged_access_fetches_a_policy_missing_its_document(make_ctx):
    iam = _ListingWithoutDocument({"Document": json.loads(_policy("*"))})
    ev = IamPrivilegedAccess().execute(_ctx_with(make_ctx, iam))
    assert iam.calls == [iam.ARN]
    assert ev.status == Status.FAIL
    assert ev.data["admin_users"] == ["u"] and ev.data["admin_policies"] == [iam.ARN]


def test_privileged_access_unresolvable_policy_is_an_error(make_ctx):
    ev = IamPrivilegedAccess().execute(_ctx_with(make_ctx, _ListingWithoutDocument({})))
    assert ev.status == Status.ERROR
    assert "no default version document" in ev.findings[0].message
