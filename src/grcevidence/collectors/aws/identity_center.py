"""IAM Identity Center evidence: administrator-equivalent permission sets and who holds them."""

from __future__ import annotations

import socket
from functools import cache
from typing import Any
from urllib.parse import urlsplit

from botocore.config import Config as BotoConfig
from botocore.exceptions import BotoCoreError, ClientError

from grcevidence.collectors.aws.policy import (
    CONDITIONAL_NOTE,
    admin_statements,
    conditional,
    fetch_document,
)
from grcevidence.collectors.base import (
    _BOTO_CONFIG,
    Collector,
    Context,
    Result,
    paginate,
    register,
    resource,
)
from grcevidence.models import Finding, Severity, Status

LIMITATIONS = [
    "Customer managed policy references are not resolved (their documents live in each member "
    "account): permission sets using them are flagged for review and their assignments recorded",
    "Permission boundaries, SCPs and explicit Deny statements are not evaluated",
]


@register
class IdentityCenter(Collector):
    id = "aws.identity_center"
    title = "IAM Identity Center administrator permission sets and assignments"
    permissions = (
        "sso:ListInstances",
        "sso:ListPermissionSets",
        "sso:DescribePermissionSet",
        "sso:ListManagedPoliciesInPermissionSet",
        "sso:GetInlinePolicyForPermissionSet",
        "sso:ListCustomerManagedPolicyReferencesInPermissionSet",
        "sso:ListAccountsForProvisionedPermissionSet",
        "sso:ListAccountAssignments",
        "identitystore:DescribeUser",
        "identitystore:DescribeGroup",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
    )

    def collect(self, ctx: Context) -> Result:
        # Commercial FIPS hosts exist only on the dual-stack domain (sso-fips.<region>.api.aws,
        # US and Canada regions); GovCloud FIPS is the standard sso./identitystore.<region> host.
        if ctx.use_fips_endpoint and ctx.partition == "aws":
            dual = _BOTO_CONFIG.merge(BotoConfig(use_dualstack_endpoint=True))
            sso, store = (
                ctx.session.client(svc, region_name=ctx.region, config=dual)
                for svc in ("sso-admin", "identitystore")
            )
        else:
            sso, store = ctx.client("sso-admin"), ctx.client("identitystore")
        if ctx.use_fips_endpoint and not all(_resolves(c) for c in (sso, store)):
            return Result(
                summary=f"Could not collect: no FIPS endpoint for IAM Identity Center in {ctx.region}",
                findings=[
                    Finding(
                        ctx.region,
                        f"No FIPS endpoint for IAM Identity Center in {ctx.region}; "
                        "permission sets and assignments were not examined",
                        Severity.MEDIUM,
                    )
                ],
                status=Status.ERROR,
            )
        instances = paginate(sso, "list_instances", "Instances")
        if not instances:
            return Result(
                summary=f"No IAM Identity Center instance in {ctx.region}",
                status=Status.NOT_APPLICABLE,
            )
        limit = ctx.params.max_items_per_check
        iam = ctx.client("iam")

        @cache  # AWS managed policies are identical in every account: this account's IAM serves
        def managed_admin(arn: str) -> list[dict[str, Any]]:
            return admin_statements(fetch_document(iam, arn))

        sets: list[dict[str, Any]] = []
        assignments: list[dict[str, Any]] = []
        findings: list[Finding] = []
        truncated = False
        for inst in instances:
            ids = {"InstanceArn": inst["InstanceArn"]}
            names: dict[str, str | None] = {}
            listed = paginate(sso, "list_permission_sets", "PermissionSets", limit, **ids)
            truncated |= listed.truncated
            for ps_arn in listed:
                if len(sets) + len(assignments) >= limit:  # one shared population cap
                    truncated = True
                    break
                ps = {**ids, "PermissionSetArn": ps_arn}
                attrs = _permission_set(sso, ps, managed_admin)
                name, admin = attrs["name"], attrs["admin"]
                unresolved = attrs["unresolved_customer_managed_policies"]
                ps_findings = []
                if unresolved:
                    ps_findings.append(
                        Finding(
                            ps_arn,
                            f"Customer-managed policy {', '.join(unresolved)} not resolved; "
                            "confirm it does not grant administrator access",
                            Severity.LOW,
                        )
                    )
                if attrs["stale_accounts"]:
                    ps_findings.append(
                        Finding(
                            ps_arn,
                            "Permission set has changes not provisioned to "
                            f"{attrs['stale_accounts']} account(s); deployed permissions may "
                            "differ from the definition",
                            Severity.MEDIUM,
                        )
                    )
                findings += ps_findings
                sets.append(resource(ps_arn, "AWS::SSO::PermissionSet", not ps_findings, **attrs))
                if not (admin or unresolved):  # unresolved may be admin: record who holds it
                    continue
                accounts = paginate(
                    sso, "list_accounts_for_provisioned_permission_set", "AccountIds", limit, **ps
                )
                truncated |= accounts.truncated
                for account in accounts:
                    got = paginate(
                        sso,
                        "list_account_assignments",
                        "AccountAssignments",
                        limit - len(sets) - len(assignments),
                        AccountId=account,
                        **ps,
                    )
                    truncated |= got.truncated
                    for a in got:
                        kind, pid = a["PrincipalType"], a["PrincipalId"]
                        key = f"{kind}:{pid}"
                        if key not in names:
                            names[key] = _principal_name(store, inst["IdentityStoreId"], kind, pid)
                        principal = names[key] or pid
                        rid = f"{account}/{name}/{kind}:{principal}"
                        direct = admin and kind == "USER"
                        if direct:
                            findings.append(
                                Finding(
                                    rid,
                                    "Administrator-equivalent permission set assigned directly "
                                    "to a user (prefer a group)"
                                    + (CONDITIONAL_NOTE if attrs["has_condition"] else ""),
                                    Severity.MEDIUM,
                                )
                            )
                        assignments.append(
                            resource(
                                rid,
                                "AWS::SSO::Assignment",
                                not direct,
                                account=account,
                                permission_set=name,
                                admin_confirmed=admin,
                                principal_type=kind,
                                principal_id=pid,
                                principal_name=principal,
                                principal_resolved=names[key] is not None,
                            )
                        )
        if not sets:
            return Result(
                summary="IAM Identity Center has no permission sets",
                data={"instances": len(instances), "resources": []},
                status=Status.NOT_APPLICABLE,
                truncated_at=limit if truncated else None,
            )
        admin_sets = sorted(s["attributes"]["name"] for s in sets if s["attributes"]["admin"])
        direct_users = sum(not a["compliant"] for a in assignments)
        return Result(
            summary=(
                f"{len(sets)} permission set(s), {len(admin_sets)} administrator-equivalent; "
                f"{len(assignments)} assignment(s) of admin or unresolved permission sets, "
                f"{direct_users} admin to user(s) directly"
            ),
            findings=findings,
            data={
                "instances": len(instances),
                "admin_permission_sets": admin_sets,
                "resources": sets + assignments,
                "limitations": LIMITATIONS,
            },
            truncated_at=limit if truncated else None,
        )


def _permission_set(sso: Any, ps: dict[str, Any], managed_admin: Any) -> dict[str, Any]:
    """The judged attributes of one permission set."""
    name = sso.describe_permission_set(**ps)["PermissionSet"]["Name"]
    managed = paginate(
        sso, "list_managed_policies_in_permission_set", "AttachedManagedPolicies", **ps
    )
    grants = {f"managed:{m['Name']}": managed_admin(m["Arn"]) for m in managed}
    inline = sso.get_inline_policy_for_permission_set(**ps).get("InlinePolicy")
    grants["inline"] = admin_statements(inline) if inline else []  # "" means no inline policy
    grants = {via: stmts for via, stmts in grants.items() if stmts}
    refs = paginate(
        sso,
        "list_customer_managed_policy_references_in_permission_set",
        "CustomerManagedPolicyReferences",
        **ps,
    )
    stale = paginate(
        sso,
        "list_accounts_for_provisioned_permission_set",
        "AccountIds",
        ProvisioningStatus="LATEST_PERMISSION_SET_NOT_PROVISIONED",
        **ps,
    )
    return {
        "name": name,
        "admin": bool(grants),
        "via": list(grants),
        "has_condition": bool(grants) and all(map(conditional, grants.values())),
        "managed_policies": sorted(m["Name"] for m in managed),
        "unresolved_customer_managed_policies": [f"{r.get('Path', '/')}{r['Name']}" for r in refs],
        "stale_accounts": len(stale),
    }


def _resolves(client: Any) -> bool:
    try:
        socket.getaddrinfo(urlsplit(client.meta.endpoint_url).hostname or "", 443)
    except (BotoCoreError, OSError):
        return False
    return True


def _principal_name(store: Any, store_id: str, kind: str, pid: str) -> str | None:
    """UserName or group DisplayName; None when the principal no longer exists."""
    try:
        if kind == "USER":
            return str(store.describe_user(IdentityStoreId=store_id, UserId=pid)["UserName"])
        return str(store.describe_group(IdentityStoreId=store_id, GroupId=pid)["DisplayName"])
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise
        return None
