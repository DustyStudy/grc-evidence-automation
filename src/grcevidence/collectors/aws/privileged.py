"""Privileged-access evidence: principals holding administrator-equivalent permissions."""

from __future__ import annotations

from functools import cache
from typing import Any

from grcevidence.collectors.aws.policy import (
    CONDITIONAL_NOTE,
    admin_statements,
    conditional,
    fetch_document,
)
from grcevidence.collectors.base import Collector, Context, Result, register, resource
from grcevidence.models import Finding, Severity

LIMITATIONS = [
    "Permission boundaries are not evaluated",
    "Service control policies and resource control policies are not evaluated",
    "Explicit Deny statements are not subtracted from Allow grants",
    "Condition keys are recorded (has_condition) but not evaluated",
    "Role trust policies and iam:PassRole escalation paths are not evaluated",
]
_KINDS = (  # GAAD list key, policy list key, CloudFormation type, data key
    ("UserDetailList", "UserPolicyList", "AWS::IAM::User", "admin_users"),
    ("GroupDetailList", "GroupPolicyList", "AWS::IAM::Group", "admin_groups"),
    ("RoleDetailList", "RolePolicyList", "AWS::IAM::Role", "admin_roles"),
)
_NAME = {"UserDetailList": "UserName", "GroupDetailList": "GroupName", "RoleDetailList": "RoleName"}


@register
class IamPrivilegedAccess(Collector):
    id = "aws.iam_privileged_access"
    title = "Principals with administrator-equivalent IAM permissions"
    scope = "global"
    permissions = (
        "iam:GetAccountAuthorizationDetails",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
    )

    def collect(self, ctx: Context) -> Result:
        iam = ctx.client("iam")
        limit = ctx.params.max_items_per_check
        details: dict[str, list[dict[str, Any]]] = {k: [] for k, *_ in _KINDS}
        details["Policies"] = []
        truncated = False
        # Customer-managed documents come in the listing; AWS managed ones (~1300) are only
        # fetched (and cached) when a principal actually has them attached.
        pages = iam.get_paginator("get_account_authorization_details").paginate(
            Filter=["User", "Group", "Role", "LocalManagedPolicy"]
        )
        for page in pages:
            for key in details:
                details[key] += page.get(key, [])
            if sum(len(details[k]) for k, *_ in _KINDS) > limit:
                truncated = True
                break

        local = {p["Arn"]: _default_document(p) for p in details["Policies"]}

        @cache
        def managed(arn: str) -> list[dict[str, Any]]:
            # A listing without the default document is fetched, never read as "no policy".
            return admin_statements(local.get(arn) or fetch_document(iam, arn))

        group_grants = {
            g["GroupName"]: _grants(g, "GroupPolicyList", managed)
            for g in details["GroupDetailList"]
        }
        findings: list[Finding] = []
        resources: list[dict[str, Any]] = []
        data: dict[str, Any] = {}
        budget = limit
        for list_key, policy_key, cfn_type, data_key in _KINDS:
            names = []
            for principal in details[list_key][:budget]:
                name = principal[_NAME[list_key]]
                grants = _grants(principal, policy_key, managed)
                direct = bool(grants)
                for group in principal.get("GroupList", []):
                    if inherited := group_grants.get(group):
                        grants.append((f"group:{group}", group, all(c for *_, c in inherited)))
                if not grants:
                    continue
                names.append(name)
                attrs: dict[str, Any] = {
                    "via": [v for v, _, _ in grants],
                    "policies": sorted({p for v, p, _ in grants if not v.startswith("group:")}),
                    "has_condition": all(c for *_, c in grants),
                }
                if list_key == "RoleDetailList":
                    attrs["service_linked"] = principal.get("Path", "").startswith(
                        "/aws-service-role/"
                    )
                flagged = list_key == "UserDetailList" and direct
                if flagged:
                    findings.append(
                        Finding(
                            name,
                            "IAM user has administrator-equivalent permissions through a directly "
                            "attached or inline policy (prefer a role or group)"
                            + (CONDITIONAL_NOTE if attrs["has_condition"] else ""),
                            Severity.MEDIUM,
                        )
                    )
                resources.append(resource(name, cfn_type, not flagged, **attrs))
            budget -= len(details[list_key][:budget])
            data[data_key] = sorted(names)

        data["admin_policies"] = sorted(arn for arn in local if managed(arn))
        examined = limit - budget
        return Result(
            summary=(
                f"{examined} principal(s) examined: {len(data['admin_users'])} user(s), "
                f"{len(data['admin_groups'])} group(s), {len(data['admin_roles'])} role(s) "
                "with administrator-equivalent permissions"
            ),
            findings=findings,
            data={
                **data,
                "resources": resources,
                "principals_examined": examined,
                "limitations": LIMITATIONS,
            },
            truncated_at=limit if truncated else None,
        )


def _grants(
    principal: dict[str, Any], policy_key: str, managed: Any
) -> list[tuple[str, str, bool]]:
    """(via label, policy name, conditional) for each policy making ``principal`` admin."""
    out = []
    for att in principal.get("AttachedManagedPolicies", []):
        stmts = managed(att["PolicyArn"])
        if stmts:
            out.append((f"managed:{att['PolicyArn']}", att["PolicyName"], conditional(stmts)))
    for inline in principal.get(policy_key, []):
        stmts = admin_statements(inline.get("PolicyDocument"))
        if stmts:
            out.append((f"inline:{inline['PolicyName']}", inline["PolicyName"], conditional(stmts)))
    return out


def _default_document(policy: dict[str, Any]) -> Any:
    return next(
        (
            v.get("Document")
            for v in policy.get("PolicyVersionList", [])
            if v.get("IsDefaultVersion")
        ),
        None,
    )
