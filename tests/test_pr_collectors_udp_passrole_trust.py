"""UDP in the security-group check, the shared CIDR helper, iam:PassRole on every role and
role trust policies. Stub clients throughout: the inputs are listing shapes, not AWS state."""

from __future__ import annotations

from types import SimpleNamespace as NS

import pytest

from grcevidence.collectors.aws.monitoring import NetworkExposure
from grcevidence.collectors.aws.policy import (
    CONDITIONAL_NOTE,
    admin_statements,
    pass_role_statements,
    trust_findings,
)
from grcevidence.collectors.aws.privileged import IamPrivilegedAccess
from grcevidence.collectors.cidr import internet_ranges
from grcevidence.models import Severity, Status

ME = "123456789012"  # conftest.ACCOUNT
OTHER = "999999999999"
V4_HALVES = ["0.0.0.0/1", "128.0.0.0/1"]


def _with_pages(make_ctx, monkeypatch, page):
    client = NS(get_paginator=lambda _op: NS(paginate=lambda **_kw: [page]))
    ctx = make_ctx()
    monkeypatch.setattr(ctx, "client", lambda *_a, **_k: client)
    return ctx


# ------------------------------------------------------------------ CIDR helper
@pytest.mark.parametrize(
    "cidrs,expected",
    [
        (["0.0.0.0/0"], ["0.0.0.0/0"]),
        (V4_HALVES, ["0.0.0.0/0"]),
        ([" 1.2.3.4/0 "], ["0.0.0.0/0"]),  # host bits and whitespace
        (["::/1", "8000::/1", "0.0.0.0/0"], ["0.0.0.0/0", "::/0"]),
        (["0.0.0.0/1", "::/1"], []),  # halves of different families do not add up
        (["10.0.0.0/8"], []),
        ([], []),
    ],
)
def test_internet_ranges(cidrs, expected):
    assert internet_ranges(cidrs) == expected


def test_internet_ranges_rejects_a_malformed_cidr():
    with pytest.raises(ValueError):
        internet_ranges(["0.0.0.0/0", "not-a-cidr"])


# ----------------------------------------------------------- security groups
def _perm(proto, cidrs, lo=22, hi=22):
    return {
        "IpProtocol": proto,
        "IpRanges": [{"CidrIp": c} for c in cidrs],
        "FromPort": lo,
        "ToPort": hi,
    }


def _exposure(make_ctx, monkeypatch, *perms):
    group = {"GroupId": "sg-1", "GroupName": "g", "IpPermissions": list(perms)}
    ctx = _with_pages(make_ctx, monkeypatch, {"SecurityGroups": [group]})
    return NetworkExposure().execute(ctx)


@pytest.mark.parametrize(
    "perms",
    [
        [_perm("udp", ["0.0.0.0/0"], lo=3389, hi=3389)],
        [_perm("17", V4_HALVES, lo=3000, hi=4000)],
        [_perm("udp", ["0.0.0.0/1"], lo=3389, hi=3389), _perm("17", ["128.0.0.0/1"], 3389, 3389)],
        [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/1"}]}, _perm("udp", ["128.0.0.0/1"], 3389, 3389)],
    ],
)  # fmt: skip
def test_udp_sensitive_port_open_to_the_internet_is_high(make_ctx, monkeypatch, perms):
    ev = _exposure(make_ctx, monkeypatch, *perms)
    assert ev.status == Status.FAIL
    assert [(f.message, f.severity) for f in ev.findings] == [
        ("Port 3389/udp open to the internet", Severity.HIGH)
    ]
    assert ev.data["resources"][0]["attributes"]["open_to_internet_ports"] == [3389]


def test_tcp_and_udp_on_the_same_port_are_reported_separately(make_ctx, monkeypatch):
    ev = _exposure(make_ctx, monkeypatch, _perm("tcp", ["0.0.0.0/0"]), _perm("udp", ["0.0.0.0/0"]))
    assert [f.message for f in ev.findings] == [
        "Port 22/tcp open to the internet",
        "Port 22/udp open to the internet",
    ]
    assert ev.data["resources"][0]["attributes"]["open_to_internet_ports"] == [22]


@pytest.mark.parametrize(
    "perms",
    [
        [_perm("tcp", ["0.0.0.0/1"]), _perm("udp", ["128.0.0.0/1"])],  # never pooled across
        [_perm("udp", ["0.0.0.0/0"], lo=53, hi=53)],  # not a sensitive port
        [_perm("udp", ["10.0.0.0/8"])],
        [_perm("icmp", ["0.0.0.0/0"], lo=-1, hi=-1)],
    ],
)
def test_udp_rules_that_do_not_expose_a_sensitive_port_pass(make_ctx, monkeypatch, perms):
    ev = _exposure(make_ctx, monkeypatch, *perms)
    assert ev.status == Status.PASS and ev.findings == []


# ------------------------------------------------------------------- PassRole
def _doc(**stmt):
    return {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", **stmt}]}


@pytest.mark.parametrize(
    "stmt",
    [
        {"Action": "iam:PassRole", "Resource": "*"},
        {"Action": ["s3:GetObject", "IAM:passrole"], "Resource": "arn:aws:iam::*:role/*"},
        {"Action": "iam:Pass*", "Resource": f"arn:aws-us-gov:iam::{ME}:role/*"},
        {"Action": "iam:*", "Resource": ["arn:aws:s3:::b", "arn:aws:iam::*:*"]},
        {"Action": "*", "Resource": "arn:*:iam::*:role*"},
        {"NotAction": "s3:*", "Resource": "*"},
        {"Action": "iam:PassRole", "NotResource": "arn:aws:s3:::b"},
    ],
)
def test_pass_role_on_every_role_is_detected(stmt):
    assert pass_role_statements(_doc(**stmt))


@pytest.mark.parametrize(
    "stmt",
    [
        {"Action": "iam:PassRole", "Resource": "arn:aws:iam::*:role/app-*"},
        {"Action": "iam:PassRole", "Resource": f"arn:aws:iam::{ME}:role/one"},
        {"Action": "iam:PassRole", "Resource": "arn:aws:iam::*:user/*"},
        {"Action": "iam:PassRole", "Resource": "arn:aws:s3:::*"},
        {"Action": "iam:GetRole", "Resource": "*"},
        {"NotAction": "iam:Pass*", "Resource": "*"},
        {"Action": "iam:PassRole", "NotResource": "arn:aws:iam::*:role/*"},
        {"Effect": "Deny", "Action": "iam:PassRole", "Resource": "*"},
    ],
)
def test_narrower_pass_role_is_not_detected(stmt):
    assert not pass_role_statements(_doc(**stmt))


def test_pass_role_is_still_not_admin_equivalent():
    assert not admin_statements(_doc(Action="iam:PassRole", Resource="*"))


def test_malformed_statement_is_an_error_not_a_pass():
    with pytest.raises(ValueError):
        pass_role_statements({"Statement": ["nope"]})


SERVICE_TRUST = _doc(Principal={"Service": "ec2.amazonaws.com"}, Action="sts:AssumeRole")


def _inline(name, **stmt):
    return [{"PolicyName": name, "PolicyDocument": _doc(**stmt)}]


def _role(name, trust=SERVICE_TRUST, path="/", **extra):
    return {"RoleName": name, "Path": path, "AssumeRolePolicyDocument": trust, **extra}


def _collect(make_ctx, monkeypatch, **page):
    return IamPrivilegedAccess().execute(_with_pages(make_ctx, monkeypatch, page))


def test_pass_role_principals_are_high_findings_beside_the_admin_finding(make_ctx, monkeypatch):
    passer = {"Action": "iam:PassRole", "Resource": "*"}
    arn = f"arn:aws:iam::{ME}:policy/pass"
    ev = _collect(
        make_ctx,
        monkeypatch,
        UserDetailList=[
            {"UserName": "admin", "UserPolicyList": _inline("all", Action="*", Resource="*")},
            {"UserName": "passer", "UserPolicyList": _inline("p", **passer)},
            {
                "UserName": "guarded",
                "AttachedManagedPolicies": [{"PolicyArn": arn, "PolicyName": "pass"}],
            },
            {"UserName": "narrow", "UserPolicyList": _inline("n", Action="s3:*", Resource="*")},
        ],
        GroupDetailList=[{"GroupName": "deployers", "GroupPolicyList": _inline("p", **passer)}],
        RoleDetailList=[
            _role("ci", RolePolicyList=_inline("p", **passer)),
            _role("AWSServiceRoleForX", path="/aws-service-role/x/", RolePolicyList=_inline("p", **passer)),
        ],
        Policies=[
            {
                "Arn": arn,
                "PolicyVersionList": [
                    {
                        "IsDefaultVersion": True,
                        "Document": _doc(
                            **passer, Condition={"StringEquals": {"iam:PassedToService": "x"}}
                        ),
                    }
                ],
            }
        ],
    )  # fmt: skip
    assert ev.status == Status.FAIL
    by_resource = {f.resource: f for f in ev.findings}
    assert sorted(by_resource) == ["admin", "ci", "deployers", "guarded", "passer"]
    assert by_resource["admin"].severity == Severity.MEDIUM  # the admin finding is unchanged
    assert "administrator-equivalent" in by_resource["admin"].message
    for name in ("passer", "guarded", "deployers", "ci"):
        assert by_resource[name].severity == Severity.HIGH
        assert "iam:PassRole on all roles" in by_resource[name].message
    assert by_resource["guarded"].message.endswith(CONDITIONAL_NOTE)
    assert not by_resource["passer"].message.endswith(CONDITIONAL_NOTE)
    assert ev.data["admin_users"] == ["admin"]
    assert ev.data["pass_role_principals"] == ["ci", "deployers", "guarded", "passer"]
    res = {r["id"]: r for r in ev.data["resources"]}
    assert "narrow" not in res and "AWSServiceRoleForX" not in res
    assert res["passer"] == {
        "id": "passer",
        "type": "AWS::IAM::User",
        "compliant": False,
        "attributes": {"pass_role_via": ["inline:p"]},
    }
    assert res["guarded"]["attributes"] == {"pass_role_via": [f"managed:{arn}"]}
    assert "pass_role_via" not in res["admin"]["attributes"]


# -------------------------------------------------------------- trust policies
ANYONE = 'Trust policy lets any AWS principal ("*") assume the role, no Condition'
EXTERNAL_ID = {"StringEquals": {"sts:ExternalId": "0123456789abcdef"}}
ORG = {"StringEquals": {"aws:PrincipalOrgID": "o-abc"}}


def _cross(account=OTHER):
    return f"Trust policy lets AWS account {account} assume the role without an sts:ExternalId condition"


@pytest.mark.parametrize(
    "stmt,expected",
    [
        ({"Principal": "*"}, [(ANYONE, Severity.HIGH)]),
        ({"Principal": {"AWS": "*"}}, [(ANYONE, Severity.HIGH)]),
        ({"Principal": {"AWS": [f"arn:aws:iam::{ME}:root", "*"]}}, [(ANYONE, Severity.HIGH)]),
        ({"NotPrincipal": {"AWS": f"arn:aws:iam::{OTHER}:root"}}, [(ANYONE, Severity.HIGH)]),
        ({"Principal": "*", "Condition": ORG}, []),
        ({"Principal": {"AWS": f"arn:aws:iam::{OTHER}:root"}}, [(_cross(), Severity.MEDIUM)]),
        ({"Principal": {"AWS": OTHER}}, [(_cross(), Severity.MEDIUM)]),
        (
            {"Principal": {"AWS": [f"arn:aws-us-gov:iam::{OTHER}:role/r", "111111111111", ME]}},
            [(_cross(), Severity.MEDIUM), (_cross("111111111111"), Severity.MEDIUM)],
        ),
        ({"Principal": {"AWS": OTHER}, "Condition": ORG}, [(_cross(), Severity.MEDIUM)]),
        ({"Principal": {"AWS": OTHER}, "Condition": EXTERNAL_ID}, []),
        ({"Principal": {"AWS": OTHER}, "Condition": {"StringLike": {"STS:externalid": "a*"}}}, []),
        ({"Principal": {"AWS": [ME, f"arn:aws:iam::{ME}:user/u"]}}, []),
        ({"Principal": {"AWS": "AROAEXAMPLEDELETEDROLE"}}, []),  # orphaned unique ID
        ({"Principal": {"Service": "ec2.amazonaws.com"}}, []),
        ({"Principal": {"Federated": f"arn:aws:iam::{ME}:saml-provider/x"}}, []),
        ({"Effect": "Deny", "Principal": "*"}, []),
    ],
)
def test_trust_findings(stmt, expected):
    assert trust_findings(_doc(Action="sts:AssumeRole", **stmt), ME) == expected


def test_trust_findings_accepts_a_url_encoded_document_and_rejects_none():
    encoded = (
        "%7B%22Statement%22%3A%7B%22Effect%22%3A%22Allow%22%2C%22Principal%22%3A%22%2A%22%7D%7D"
    )
    assert trust_findings(encoded, ME) == [(ANYONE, Severity.HIGH)]
    with pytest.raises(ValueError):
        trust_findings(None, ME)


def test_role_trust_policies_are_evaluated(make_ctx, monkeypatch):
    def trust(**stmt):
        return _doc(Action="sts:AssumeRole", **stmt)

    ev = _collect(
        make_ctx,
        monkeypatch,
        RoleDetailList=[
            _role("open", trust(Principal={"AWS": "*"})),
            _role("vendor", trust(Principal={"AWS": f"arn:aws:iam::{OTHER}:root"})),
            _role("vendor-ok", trust(Principal={"AWS": OTHER}, Condition=EXTERNAL_ID)),
            _role("same-account", trust(Principal={"AWS": f"arn:aws:iam::{ME}:root"})),
            _role("service"),
            _role(
                "open-admin",
                trust(Principal="*"),
                RolePolicyList=_inline("all", Action="*", Resource="*"),
            ),
        ],
    )
    assert ev.status == Status.FAIL
    assert [(f.resource, f.message, f.severity) for f in ev.findings] == [
        ("open", ANYONE, Severity.HIGH),
        ("vendor", _cross(), Severity.MEDIUM),
        ("open-admin", ANYONE, Severity.HIGH),
    ]
    assert ev.data["role_trust_findings"] == 3
    assert ev.data["admin_roles"] == ["open-admin"]
    res = {r["id"]: r for r in ev.data["resources"]}
    assert sorted(res) == ["open", "open-admin", "vendor"]
    assert res["vendor"] == {
        "id": "vendor",
        "type": "AWS::IAM::Role",
        "compliant": False,
        "attributes": {"trust_findings": [_cross()], "service_linked": False},
    }
    assert res["open-admin"]["compliant"] is False
    assert res["open-admin"]["attributes"]["via"] == ["inline:all"]
    assert not any("not evaluated" in n and "PassRole" in n for n in ev.data["limitations"])


def test_role_without_a_trust_document_is_an_error(make_ctx, monkeypatch):
    ev = _collect(make_ctx, monkeypatch, RoleDetailList=[{"RoleName": "r", "Path": "/"}])
    assert ev.status == Status.ERROR
