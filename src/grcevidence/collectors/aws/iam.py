"""IAM evidence: MFA, password policy, access-key hygiene, privileged access."""

from __future__ import annotations

import csv
import io
import time
from datetime import datetime
from typing import Any

from botocore.exceptions import ClientError

from grcevidence.collectors.base import Collector, Context, Result, register
from grcevidence.models import Finding, Severity, Status

ROOT = "<root_account>"


def credential_report(iam: Any, *, attempts: int = 10, delay: float = 2.0) -> list[dict[str, str]]:
    """Generate (waiting for completion) and parse the IAM credential report."""
    for _ in range(attempts):
        if iam.generate_credential_report()["State"] == "COMPLETE":
            break
        time.sleep(delay)
    content: bytes = iam.get_credential_report()["Content"]
    return list(csv.DictReader(io.StringIO(content.decode("utf-8"))))


def _parse_ts(value: str) -> datetime | None:
    if not value or value in {"N/A", "no_information", "not_supported"}:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


@register
class IamMfa(Collector):
    id = "aws.iam_mfa"
    title = "MFA on root account and console users"
    scope = "global"
    permissions = (
        "iam:GetAccountSummary",
        "iam:GenerateCredentialReport",
        "iam:GetCredentialReport",
    )

    def collect(self, ctx: Context) -> Result:
        iam = ctx.client("iam")
        root_mfa = iam.get_account_summary()["SummaryMap"].get("AccountMFAEnabled", 0) == 1
        rows = credential_report(iam)
        users = [r for r in rows if r["user"] != ROOT]
        console = [r for r in users if r.get("password_enabled") == "true"]
        no_mfa = [r for r in console if r.get("mfa_active") != "true"]

        findings: list[Finding] = []
        if not root_mfa:
            findings.append(
                Finding("root", "Root account does not have MFA enabled", Severity.CRITICAL)
            )
        findings += [
            Finding(r["user"], "Console access enabled without MFA", Severity.HIGH) for r in no_mfa
        ]
        return Result(
            summary=(
                f"Root MFA {'enabled' if root_mfa else 'DISABLED'}; "
                f"{len(console) - len(no_mfa)}/{len(console)} console users have MFA"
            ),
            findings=findings,
            data={
                "root_mfa_enabled": root_mfa,
                "iam_users": len(users),
                "console_users": len(console),
                "console_users_without_mfa": len(no_mfa),
            },
        )


@register
class IamPasswordPolicy(Collector):
    id = "aws.iam_password_policy"
    title = "IAM account password policy"
    scope = "global"
    permissions = ("iam:GetAccountPasswordPolicy",)

    def collect(self, ctx: Context) -> Result:
        iam = ctx.client("iam")
        try:
            policy = iam.get_account_password_policy()["PasswordPolicy"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
            return Result(
                summary="No account password policy is set (AWS defaults apply)",
                findings=[Finding("account", "No IAM password policy configured", Severity.HIGH)],
                data={"policy_configured": False},
            )
        p = ctx.params
        findings: list[Finding] = []
        length = int(policy.get("MinimumPasswordLength", 0))
        reuse = int(policy.get("PasswordReusePrevention", 0))
        if length < p.password_min_length:
            findings.append(
                Finding(
                    "account",
                    f"Minimum length {length} < required {p.password_min_length}",
                    Severity.MEDIUM,
                )
            )
        if reuse < p.password_reuse_prevention:
            findings.append(
                Finding(
                    "account",
                    f"Password reuse prevention {reuse} < required {p.password_reuse_prevention}",
                    Severity.LOW,
                )
            )
        for flag in (
            "RequireUppercaseCharacters",
            "RequireLowercaseCharacters",
            "RequireNumbers",
            "RequireSymbols",
        ):
            if not policy.get(flag):
                findings.append(Finding("account", f"{flag} is not enabled", Severity.LOW))
        return Result(
            summary=f"Password policy: min length {length}, reuse prevention {reuse}",
            findings=findings,
            data={
                "policy_configured": True,
                "minimum_length": length,
                "reuse_prevention": reuse,
                "max_password_age": policy.get("MaxPasswordAge"),
                "require_uppercase": bool(policy.get("RequireUppercaseCharacters")),
                "require_lowercase": bool(policy.get("RequireLowercaseCharacters")),
                "require_numbers": bool(policy.get("RequireNumbers")),
                "require_symbols": bool(policy.get("RequireSymbols")),
            },
        )


@register
class IamAccessKeys(Collector):
    id = "aws.iam_access_keys"
    title = "IAM access-key age, usage and root keys"
    scope = "global"
    permissions = ("iam:GenerateCredentialReport", "iam:GetCredentialReport")

    def collect(self, ctx: Context) -> Result:
        rows = credential_report(ctx.client("iam"))
        p, now = ctx.params, ctx.now
        findings: list[Finding] = []
        active_keys = 0
        for r in rows:
            who = "root" if r["user"] == ROOT else r["user"]
            for n in ("1", "2"):
                if r.get(f"access_key_{n}_active") != "true":
                    continue
                active_keys += 1
                if r["user"] == ROOT:
                    findings.append(
                        Finding(
                            who, f"Root account has an active access key ({n})", Severity.CRITICAL
                        )
                    )
                    continue
                rotated = _parse_ts(r.get(f"access_key_{n}_last_rotated", ""))
                used = _parse_ts(r.get(f"access_key_{n}_last_used_date", ""))
                if rotated and (now - rotated).days > p.max_access_key_age_days:
                    findings.append(
                        Finding(
                            who,
                            f"Access key {n} is {(now - rotated).days} days old (max {p.max_access_key_age_days})",
                            Severity.MEDIUM,
                        )
                    )
                idle_ref = used or rotated
                if idle_ref and (now - idle_ref).days > p.max_access_key_unused_days:
                    verb = "last used" if used else "never used since creation"
                    findings.append(
                        Finding(
                            who,
                            f"Access key {n} {verb} {(now - idle_ref).days} days ago (max idle {p.max_access_key_unused_days})",
                            Severity.MEDIUM,
                        )
                    )
        return Result(
            summary=f"{active_keys} active access key(s) across {len(rows) - 1} IAM user(s); {len(findings)} finding(s)",
            findings=findings,
            data={"iam_users": len(rows) - 1, "active_access_keys": active_keys},
        )


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
