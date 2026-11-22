"""Privileged-access evidence from one IAM account-authorization listing.

Scope:
- principals holding administrator-equivalent permissions (``policy.admin_statements``);
- principals that are not administrator-equivalent but hold ``iam:PassRole`` on every role
  (HIGH: they can run code as any role a service can assume);
- role trust policies: any AWS principal with no Condition (HIGH), or another AWS account
  with no ``sts:ExternalId`` condition (MEDIUM).
What is still not evaluated is listed in ``LIMITATIONS`` and written into the evidence.
"""

from __future__ import annotations

from functools import cache
from typing import Any

from grcevidence.collectors.aws.policy import (
    CONDITIONAL_NOTE,
    admin_statements,
    conditional,
    fetch_document,
    pass_role_statements,
    trust_findings,
)
from grcevidence.collectors.base import Collector, Context, Result, register, resource
from grcevidence.models import Finding, Severity

LIMITATIONS = [
    "Permission boundaries are not evaluated",
    "Service control policies and resource control policies are not evaluated",
    "Explicit Deny statements are not subtracted from Allow grants",
    "Condition keys are recorded (has_condition) but not evaluated",
    "iam:PassRole is reported only when it covers every role, only for principals that are not "
    "already administrator-equivalent or service-linked, and on the policy holder (members of "
    "a group that holds it are not listed)",
    "Role trust policies are checked for wildcard and other-account AWS principals only; "
    "service and federated principals and who can reach a trusted principal are not evaluated",
]
_ANALYSES = (admin_statements, pass_role_statements)  # the "kind" index used by _grants
_ESCALATION = (
    "Can pass any role to a service (iam:PassRole on all roles): a privilege-escalation path "
    "to every role a service can assume"
)
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
        def managed(arn: str) -> tuple[list[dict[str, Any]], ...]:
            # A listing without the default document is fetched, never read as "no policy".
            document = local.get(arn) or fetch_document(iam, arn)
            return tuple(analyse(document) for analyse in _ANALYSES)

        group_grants = {
            g["GroupName"]: _grants(g, "GroupPolicyList", managed)
            for g in details["GroupDetailList"]
        }
        pass_role: list[str] = []
        trust_count = 0
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
                service_linked = principal.get("Path", "").startswith("/aws-service-role/")
                attrs: dict[str, Any] = {}
                extra: list[Finding] = []  # PassRole and trust findings, beside the admin one
                if grants:
                    names.append(name)
                    attrs = {
                        "via": [v for v, _, _ in grants],
                        "policies": sorted({p for v, p, _ in grants if not v.startswith("group:")}),
                        "has_condition": all(c for *_, c in grants),
                    }
                # An administrator can already pass any role; a service-linked role's policy
                # is AWS-owned and cannot be changed.
                elif not service_linked and (passes := _grants(principal, policy_key, managed, 1)):
                    pass_role.append(name)
                    attrs["pass_role_via"] = [v for v, _, _ in passes]
                    note = CONDITIONAL_NOTE if all(c for *_, c in passes) else ""
                    extra.append(Finding(name, _ESCALATION + note, Severity.HIGH))
                if list_key == "RoleDetailList":
                    trust = trust_findings(principal.get("AssumeRolePolicyDocument"), ctx.account)
                    if trust:
                        trust_count += len(trust)
                        attrs["trust_findings"] = [message for message, _ in trust]
                        extra += [Finding(name, message, sev) for message, sev in trust]
                if not attrs:
                    continue
                if list_key == "RoleDetailList":
                    attrs["service_linked"] = service_linked
                findings += extra
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
                resources.append(resource(name, cfn_type, not (flagged or extra), **attrs))
            budget -= len(details[list_key][:budget])
            data[data_key] = sorted(names)

        data["admin_policies"] = sorted(arn for arn in local if managed(arn)[0])
        data["pass_role_principals"] = sorted(pass_role)
        data["role_trust_findings"] = trust_count
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
    principal: dict[str, Any], policy_key: str, managed: Any, kind: int = 0
) -> list[tuple[str, str, bool]]:
    """(via label, policy name, conditional) for each policy making ``principal`` admin
    (``kind`` 0) or letting it pass any role (``kind`` 1)."""
    out = []
    for att in principal.get("AttachedManagedPolicies", []):
        stmts = managed(att["PolicyArn"])[kind]
        if stmts:
            out.append((f"managed:{att['PolicyArn']}", att["PolicyName"], conditional(stmts)))
    for inline in principal.get(policy_key, []):
        stmts = _ANALYSES[kind](inline.get("PolicyDocument"))
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
