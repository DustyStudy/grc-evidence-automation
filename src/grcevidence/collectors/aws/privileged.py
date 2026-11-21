"""Privileged-access evidence: principals holding administrator-equivalent permissions."""

from __future__ import annotations

from grcevidence.collectors.base import Collector, Context, Result, register
from grcevidence.models import Finding, Severity, Status

ADMIN_POLICY = "AdministratorAccess"


@register
class IamPrivilegedAccess(Collector):
    id = "aws.iam_privileged_access"
    title = "Principals holding AdministratorAccess"
    scope = "global"
    permissions = ("iam:ListEntitiesForPolicy",)

    def collect(self, ctx: Context) -> Result:
        iam = ctx.client("iam")
        arn = f"arn:{ctx.partition}:iam::aws:policy/{ADMIN_POLICY}"
        users: list[str] = []
        groups: list[str] = []
        roles: list[str] = []
        for page in iam.get_paginator("list_entities_for_policy").paginate(PolicyArn=arn):
            users += [u["UserName"] for u in page.get("PolicyUsers", [])]
            groups += [g["GroupName"] for g in page.get("PolicyGroups", [])]
            roles += [r["RoleName"] for r in page.get("PolicyRoles", [])]
        findings = [
            Finding(
                u,
                f"IAM user has {ADMIN_POLICY} attached directly (prefer role/group with MFA)",
                Severity.MEDIUM,
            )
            for u in users
        ]
        return Result(
            summary=f"{ADMIN_POLICY}: {len(users)} user(s), {len(groups)} group(s), {len(roles)} role(s)",
            findings=findings,
            data={
                "admin_users": sorted(users),
                "admin_groups": sorted(groups),
                "admin_roles": sorted(roles),
            },
            status=Status.FAIL if findings else Status.PASS,
        )
