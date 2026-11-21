"""IAM evidence: MFA, password policy and access-key hygiene."""

from __future__ import annotations

import csv
import io
import time
from datetime import datetime
from typing import Any

from botocore.exceptions import ClientError

from grcevidence.collectors.base import Collector, Context, Result, register, resource
from grcevidence.models import Finding, Severity

ROOT = "<root_account>"
_POLICY = "AWS::IAM::AccountPasswordPolicy"


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
        all_users = [r for r in rows if r["user"] != ROOT]
        cap = ctx.params.max_items_per_check
        users = all_users[: max(cap - 1, 0)]  # root takes one slot of the capped population
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
        resources = [resource("root", "AWS::::Account", root_mfa, mfa_active=root_mfa)]
        for r in users:
            has_console = r.get("password_enabled") == "true"
            has_mfa = r.get("mfa_active") == "true"
            resources.append(
                resource(
                    r["user"],
                    "AWS::IAM::User",
                    has_mfa or not has_console,
                    console_access=has_console,
                    mfa_active=has_mfa,
                )
            )
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
                "resources": resources,
            },
            truncated_at=cap if len(all_users) > len(users) else None,
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
                data={
                    "policy_configured": False,
                    "resources": [resource("account", _POLICY, False, policy_configured=False)],
                },
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
        # NIST SP 800-63B-4 (which FedRAMP's IA-5 guidance points to) says verifiers SHALL NOT
        # impose composition rules, so missing composition rules are only a finding when the
        # organization's own policy requires them (parameters.password_require_composition).
        if p.password_require_composition:
            for flag in (
                "RequireUppercaseCharacters",
                "RequireLowercaseCharacters",
                "RequireNumbers",
                "RequireSymbols",
            ):
                if not policy.get(flag):
                    findings.append(Finding("account", f"{flag} is not enabled", Severity.LOW))
        judged: dict[str, Any] = {"minimum_length": length, "reuse_prevention": reuse}
        if p.password_require_composition:
            judged.update(
                require_uppercase=bool(policy.get("RequireUppercaseCharacters")),
                require_lowercase=bool(policy.get("RequireLowercaseCharacters")),
                require_numbers=bool(policy.get("RequireNumbers")),
                require_symbols=bool(policy.get("RequireSymbols")),
            )
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
                "resources": [resource("account", _POLICY, not findings, **judged)],
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
        active = [
            (r, n) for r in rows for n in ("1", "2") if r.get(f"access_key_{n}_active") == "true"
        ]
        keys = active[: p.max_items_per_check]
        findings: list[Finding] = []
        resources: list[dict[str, Any]] = []
        for r, n in keys:
            who = "root" if r["user"] == ROOT else r["user"]
            before = len(findings)
            rotated = _parse_ts(r.get(f"access_key_{n}_last_rotated", ""))
            used = _parse_ts(r.get(f"access_key_{n}_last_used_date", ""))
            # The access key ID is left out on purpose: user and slot identify the key.
            rid = f"{who}/access_key_{n}"
            attrs = {
                "age_days": (now - rotated).days if rotated else None,
                "last_used_days": (now - used).days if used else None,
                "never_used": used is None,
            }
            if r["user"] == ROOT:
                findings.append(
                    Finding(who, f"Root account has an active access key ({n})", Severity.CRITICAL)
                )
            else:
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
            resources.append(resource(rid, "AWS::IAM::AccessKey", len(findings) == before, **attrs))
        return Result(
            summary=f"{len(keys)} active access key(s) across {len(rows) - 1} IAM user(s); {len(findings)} finding(s)",
            findings=findings,
            data={
                "iam_users": len(rows) - 1,
                "active_access_keys": len(keys),
                "resources": resources,
            },
            truncated_at=p.max_items_per_check if len(active) > len(keys) else None,
        )
