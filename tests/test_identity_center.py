"""aws.identity_center. moto models every sso-admin, identitystore and IAM call the collector makes
(it always creates one Identity Center instance per region, so the no-instance case clears moto's
backend; AWS managed policies need MOTO_IAM_LOAD_MANAGED_POLICIES). One gap is stubbed: moto 5.2
ignores ListAccountsForProvisionedPermissionSet's ProvisioningStatus filter (every provisioned set
would read as stale), so the autouse `stale` fixture patches moto's response handler to answer
that filter from a dict the test fills. The FIPS tests use the real FIPS session with
socket.getaddrinfo patched (moto does not match the dual-stack .api.aws FIPS hosts, so a
before-send hook answers ListInstances), and the non-NotFound identitystore error uses a tiny
fake client."""

from __future__ import annotations

import io
import json
import socket

import pytest
from botocore.awsrequest import AWSResponse
from botocore.exceptions import ClientError
from moto.ssoadmin.models import ssoadmin_backends
from moto.ssoadmin.responses import SSOAdminResponse

from grcevidence.collectors.aws.identity_center import IdentityCenter, _principal_name
from grcevidence.collectors.aws.policy import CONDITIONAL_NOTE
from grcevidence.models import Status
from grcevidence.runner import aws_session as real_aws_session  # bound before conftest patches
from tests.conftest import ACCOUNT

ADMIN_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
NOT_PROVISIONED = "LATEST_PERMISSION_SET_NOT_PROVISIONED"
IAM_FULL = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}],
    }
)


@pytest.fixture(autouse=True)
def stale(monkeypatch):
    """Permission set ARN -> accounts whose provisioning is behind its definition."""
    monkeypatch.setenv("MOTO_IAM_LOAD_MANAGED_POLICIES", "true")
    behind: dict[str, list[str]] = {}
    real = SSOAdminResponse.list_accounts_for_provisioned_permission_set

    def honour_status(self):
        if self._get_param("ProvisioningStatus") == NOT_PROVISIONED:
            return json.dumps({"AccountIds": behind.get(self._get_param("PermissionSetArn"), [])})
        return real(self)

    monkeypatch.setattr(
        SSOAdminResponse, "list_accounts_for_provisioned_permission_set", honour_status
    )
    return behind


def _setup(session, admin_sets=("Admin",), read_only=True):
    sso = session.client("sso-admin")
    inst = sso.list_instances()["Instances"][0]
    ia, store_id = inst["InstanceArn"], inst["IdentityStoreId"]

    def make(name):
        arn = sso.create_permission_set(Name=name, InstanceArn=ia)["PermissionSet"][
            "PermissionSetArn"
        ]
        sso.provision_permission_set(
            InstanceArn=ia, PermissionSetArn=arn, TargetType="ALL_PROVISIONED_ACCOUNTS"
        )
        return arn

    arns = {}
    for name in admin_sets:
        arns[name] = make(name)
        sso.attach_managed_policy_to_permission_set(
            InstanceArn=ia, PermissionSetArn=arns[name], ManagedPolicyArn=ADMIN_ARN
        )
    if read_only:
        ro = make("ReadOnly")
        sso.attach_managed_policy_to_permission_set(
            InstanceArn=ia,
            PermissionSetArn=ro,
            ManagedPolicyArn="arn:aws:iam::aws:policy/ReadOnlyAccess",
        )
        sso.attach_customer_managed_policy_reference_to_permission_set(
            InstanceArn=ia,
            PermissionSetArn=ro,
            CustomerManagedPolicyReference={"Name": "local", "Path": "/x/"},
        )
    return sso, session.client("identitystore"), ia, store_id, arns


def _assign(sso, ia, ps_arn, kind, pid):
    sso.create_account_assignment(
        InstanceArn=ia,
        TargetId=ACCOUNT,
        TargetType="AWS_ACCOUNT",
        PermissionSetArn=ps_arn,
        PrincipalType=kind,
        PrincipalId=pid,
    )


def test_identity_center_flags_admin_assigned_to_users(make_ctx, session):
    sso, store, ia, store_id, arns = _setup(session)
    inline = sso.create_permission_set(Name="InlineAdmin", InstanceArn=ia)["PermissionSet"][
        "PermissionSetArn"
    ]
    sso.put_inline_policy_to_permission_set(
        InstanceArn=ia, PermissionSetArn=inline, InlinePolicy=IAM_FULL
    )
    sso.provision_permission_set(
        InstanceArn=ia, PermissionSetArn=inline, TargetType="ALL_PROVISIONED_ACCOUNTS"
    )
    uid = store.create_user(
        IdentityStoreId=store_id,
        UserName="erin",
        DisplayName="Erin",
        Name={"GivenName": "E", "FamilyName": "R"},
    )["UserId"]
    gid = store.create_group(IdentityStoreId=store_id, DisplayName="platform-admins")["GroupId"]
    _assign(sso, ia, arns["Admin"], "USER", uid)
    _assign(sso, ia, arns["Admin"], "USER", "gone-user")  # deleted principal: id is kept
    _assign(sso, ia, inline, "GROUP", gid)

    ev = IdentityCenter().execute(make_ctx())

    ro = next(r for r in ev.data["resources"] if r["attributes"].get("name") == "ReadOnly")
    assert ev.status == Status.FAIL
    assert sorted((f.resource, f.severity.value) for f in ev.findings) == [
        (f"{ACCOUNT}/Admin/USER:erin", "medium"),
        (f"{ACCOUNT}/Admin/USER:gone-user", "medium"),
        (ro["id"], "low"),
    ]
    assert ev.data["admin_permission_sets"] == ["Admin", "InlineAdmin"]
    res = {r["id"]: r for r in ev.data["resources"]}
    assert res[arns["Admin"]]["attributes"]["via"] == ["managed:AdministratorAccess"]
    assert res[arns["Admin"]]["compliant"] is True
    assert res[inline]["attributes"]["via"] == ["inline"]
    assert ro["type"] == "AWS::SSO::PermissionSet" and ro["compliant"] is False
    assert ro["attributes"]["admin"] is False
    assert ro["attributes"]["managed_policies"] == ["ReadOnlyAccess"]
    assert ro["attributes"]["unresolved_customer_managed_policies"] == ["/x/local"]
    assert ro["attributes"]["stale_accounts"] == 0
    group = res[f"{ACCOUNT}/InlineAdmin/GROUP:platform-admins"]
    assert group["type"] == "AWS::SSO::Assignment" and group["compliant"] is True
    assert group["attributes"]["principal_id"] == gid
    assert group["attributes"]["principal_resolved"] is True
    assert res[f"{ACCOUNT}/Admin/USER:erin"]["compliant"] is False
    gone = res[f"{ACCOUNT}/Admin/USER:gone-user"]["attributes"]
    assert gone["principal_resolved"] is False and gone["principal_name"] == "gone-user"
    assert ev.data["limitations"]


def test_identity_center_without_instance_is_not_applicable(make_ctx):
    ssoadmin_backends[ACCOUNT]["us-east-1"].instances.clear()
    assert IdentityCenter().execute(make_ctx()).status == Status.NOT_APPLICABLE


def test_identity_center_without_permission_sets_is_not_applicable(make_ctx):
    assert IdentityCenter().execute(make_ctx()).status == Status.NOT_APPLICABLE


def test_identity_center_group_only_admin_passes(make_ctx, session):
    sso, store, ia, store_id, arns = _setup(session, read_only=False)
    gid = store.create_group(IdentityStoreId=store_id, DisplayName="admins")["GroupId"]
    _assign(sso, ia, arns["Admin"], "GROUP", gid)
    ev = IdentityCenter().execute(make_ctx())
    assert ev.status == Status.PASS
    assert len(ev.data["resources"]) == 2


def test_identity_center_respects_the_cap(make_ctx, session):
    sso, store, ia, store_id, arns = _setup(session, admin_sets=("A", "B"), read_only=False)
    for name in ("A", "B"):
        _assign(sso, ia, arns[name], "USER", f"u-{name}")
    ev = IdentityCenter().execute(make_ctx(max_items_per_check=1))
    assert ev.data["truncated"] is True
    assert len(ev.data["resources"]) == 1


@pytest.mark.parametrize(
    ("region", "hosts"),
    [
        ("eu-west-1", ["sso-fips.eu-west-1.api.aws", "identitystore-fips.eu-west-1.api.aws"]),
        (
            "cn-north-1",
            [
                "sso-fips.cn-north-1.amazonaws.com.cn",
                "identitystore-fips.cn-north-1.amazonaws.com.cn",
            ],
        ),
    ],
)
def test_identity_center_without_fips_endpoint_is_an_error(make_ctx, monkeypatch, region, hosts):
    seen = []

    def no_dns(host, *_args, **_kwargs):
        seen.append(host)
        raise socket.gaierror("no address")

    monkeypatch.setattr(socket, "getaddrinfo", no_dns)
    ctx = make_ctx(region)
    ctx.session, ctx.use_fips_endpoint = real_aws_session(True, region_name=region), True
    ev = IdentityCenter().execute(ctx)
    assert ev.status == Status.ERROR
    assert f"no FIPS endpoint for IAM Identity Center in {region}" in ev.summary
    assert seen == hosts[:1]  # the first unresolvable host settles it


class _Raw(io.BytesIO):
    def stream(self, **_kwargs):
        yield self.getvalue()


@pytest.mark.parametrize(
    ("region", "hosts"),
    [
        ("us-east-1", ["sso-fips.us-east-1.api.aws", "identitystore-fips.us-east-1.api.aws"]),
        (
            "us-gov-west-1",
            ["sso.us-gov-west-1.amazonaws.com", "identitystore.us-gov-west-1.amazonaws.com"],
        ),
    ],
)
def test_identity_center_with_reachable_fips_endpoint_collects(
    make_ctx, monkeypatch, region, hosts
):
    """moto only matches *.amazonaws.com, so ListInstances is answered by a before-send hook."""
    seen, urls = [], []
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port: seen.append(host) or [])
    ctx = make_ctx(region)
    ctx.session, ctx.use_fips_endpoint = real_aws_session(True, region_name=region), True

    def no_instances(request, **_kwargs):
        urls.append(request.url)
        return AWSResponse(request.url, 200, {}, _Raw(b'{"Instances": []}'))

    ctx.session.events.register("before-send.sso-admin.ListInstances", no_instances)
    assert IdentityCenter().execute(ctx).status == Status.NOT_APPLICABLE
    assert seen == hosts
    assert urls == [f"https://{hosts[0]}/"]


def test_principal_name_reraises_other_errors():
    class Store:
        def describe_group(self, **_kw):
            raise ClientError({"Error": {"Code": "AccessDeniedException"}}, "DescribeGroup")

    with pytest.raises(ClientError):
        _principal_name(Store(), "d-1", "GROUP", "g-1")


def test_identity_center_cap_stops_before_the_next_permission_set(make_ctx, session):
    sso, _, ia, _, arns = _setup(session, admin_sets=("A", "B"), read_only=False)
    _assign(sso, ia, arns["A"], "USER", "u-1")
    ev = IdentityCenter().execute(make_ctx(max_items_per_check=2))
    assert ev.data["truncated"] is True
    assert [r["type"] for r in ev.data["resources"]] == [
        "AWS::SSO::PermissionSet",
        "AWS::SSO::Assignment",
    ]


@pytest.mark.parametrize(
    "policy,admin",
    [
        ("AdministratorAccess", True),
        ("IAMFullAccess", True),  # iam:* on * can attach AdministratorAccess to itself
        ("PowerUserAccess", True),  # Allow + NotAction on *
        ("ReadOnlyAccess", False),
    ],
)
def test_identity_center_resolves_aws_managed_policies(make_ctx, session, policy, admin):
    sso, _, ia, _, _ = _setup(session, admin_sets=(), read_only=False)
    for name in ("One", "Two"):  # the same policy on two sets is fetched once
        arn = sso.create_permission_set(Name=name, InstanceArn=ia)["PermissionSet"][
            "PermissionSetArn"
        ]
        sso.attach_managed_policy_to_permission_set(
            InstanceArn=ia,
            PermissionSetArn=arn,
            ManagedPolicyArn=f"arn:aws:iam::aws:policy/{policy}",
        )
    calls = []
    session.events.register("before-call.iam.GetPolicy", lambda **_kw: calls.append(1))
    ev = IdentityCenter().execute(make_ctx())
    assert ev.status == Status.PASS
    assert len(calls) == 1
    assert ev.data["admin_permission_sets"] == (["One", "Two"] if admin else [])
    for r in ev.data["resources"]:
        assert r["attributes"]["via"] == ([f"managed:{policy}"] if admin else [])


def test_identity_center_unresolved_customer_policy_is_never_a_silent_pass(make_ctx, session):
    sso, store, ia, store_id, _ = _setup(session, admin_sets=())
    ro = sso.list_permission_sets(InstanceArn=ia)["PermissionSets"][0]
    gid = store.create_group(IdentityStoreId=store_id, DisplayName="ops")["GroupId"]
    _assign(sso, ia, ro, "GROUP", gid)
    _assign(sso, ia, ro, "USER", "u-1")
    ev = IdentityCenter().execute(make_ctx())
    assert ev.status == Status.FAIL
    assert [(f.resource, f.severity.value) for f in ev.findings] == [(ro, "low")]
    assert "/x/local not resolved" in ev.findings[0].message
    res = {r["id"]: r for r in ev.data["resources"]}
    assert res[ro]["compliant"] is False
    held = [r for r in ev.data["resources"] if r["type"] == "AWS::SSO::Assignment"]
    assert sorted(r["id"] for r in held) == [
        f"{ACCOUNT}/ReadOnly/GROUP:ops",
        f"{ACCOUNT}/ReadOnly/USER:u-1",
    ]
    assert all(r["compliant"] and r["attributes"]["admin_confirmed"] is False for r in held)


def test_identity_center_flags_unprovisioned_changes_on_any_set(make_ctx, session, stale):
    sso, _, ia, _, _ = _setup(session, admin_sets=(), read_only=False)
    arn = sso.create_permission_set(Name="Plain", InstanceArn=ia)["PermissionSet"][
        "PermissionSetArn"
    ]
    stale[arn] = ["111111111111", "222222222222"]
    ev = IdentityCenter().execute(make_ctx())
    assert ev.status == Status.FAIL
    assert [(f.resource, f.severity.value) for f in ev.findings] == [(arn, "medium")]
    assert "not provisioned to 2 account(s)" in ev.findings[0].message
    (ps,) = ev.data["resources"]
    assert ps["compliant"] is False and ps["attributes"]["stale_accounts"] == 2
    assert ps["attributes"]["admin"] is False


def test_identity_center_notes_a_conditional_admin_grant(make_ctx, session):
    sso, _, ia, _, _ = _setup(session, admin_sets=(), read_only=False)
    arn = sso.create_permission_set(Name="MfaAdmin", InstanceArn=ia)["PermissionSet"][
        "PermissionSetArn"
    ]
    doc = json.loads(IAM_FULL)
    doc["Statement"][0]["Condition"] = {"Bool": {"aws:MultiFactorAuthPresent": "true"}}
    sso.put_inline_policy_to_permission_set(
        InstanceArn=ia, PermissionSetArn=arn, InlinePolicy=json.dumps(doc)
    )
    sso.provision_permission_set(
        InstanceArn=ia, PermissionSetArn=arn, TargetType="ALL_PROVISIONED_ACCOUNTS"
    )
    _assign(sso, ia, arn, "USER", "u-1")
    ev = IdentityCenter().execute(make_ctx())
    (finding,) = ev.findings
    assert finding.message.endswith(CONDITIONAL_NOTE)
    assert ev.data["resources"][0]["attributes"]["has_condition"] is True
