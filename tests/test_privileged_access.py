from __future__ import annotations

from grcevidence.collectors.aws.privileged import IamPrivilegedAccess
from grcevidence.models import Status


def test_privileged_access_flags_direct_user_admin(make_ctx, session, monkeypatch):
    monkeypatch.setenv("MOTO_IAM_LOAD_MANAGED_POLICIES", "true")  # AdministratorAccess must exist
    iam = session.client("iam")
    arn = "arn:aws:iam::aws:policy/AdministratorAccess"
    iam.create_user(UserName="erin")
    iam.attach_user_policy(UserName="erin", PolicyArn=arn)
    iam.create_group(GroupName="admins")
    iam.attach_group_policy(GroupName="admins", PolicyArn=arn)
    ev = IamPrivilegedAccess().execute(make_ctx())
    assert ev.status == Status.FAIL
    assert ev.data["admin_users"] == ["erin"] and ev.data["admin_groups"] == ["admins"]


def test_privileged_access_clean_account_passes(make_ctx):
    assert IamPrivilegedAccess().execute(make_ctx()).status == Status.PASS
