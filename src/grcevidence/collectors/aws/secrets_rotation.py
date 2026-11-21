"""Secrets evidence: Secrets Manager rotation, judged from ListSecrets metadata only.

Secret values are never read: no GetSecretValue, and no tags or descriptions are recorded.
"""

from __future__ import annotations

import math
import re
from datetime import UTC
from typing import Any

from grcevidence.collectors.base import Collector, Context, Result, paginate, register, resource
from grcevidence.models import Finding, Severity, Status, utc_iso

_RATE = re.compile(r"rate\((\d+) (hour|day)s?\)")


def _rotation_days(rules: dict[str, Any]) -> int | None:
    """Rotation interval in days, or None for a cron() schedule (interval not fixed)."""
    if rules.get("AutomaticallyAfterDays"):
        return int(rules["AutomaticallyAfterDays"])
    match = _RATE.fullmatch(rules.get("ScheduleExpression", ""))
    if not match:
        return None
    n, unit = int(match[1]), match[2]
    return n if unit == "day" else math.ceil(n / 24)


@register
class SecretsRotation(Collector):
    id = "aws.secrets_rotation"
    title = "Secrets Manager secret rotation"
    permissions = ("secretsmanager:ListSecrets",)

    def collect(self, ctx: Context) -> Result:
        max_days = ctx.params.max_secret_rotation_days
        secrets = paginate(
            ctx.client("secretsmanager"),
            "list_secrets",
            "SecretList",
            ctx.params.max_items_per_check,
        )
        findings: list[Finding] = []
        resources = []
        for secret in secrets:
            arn = secret["ARN"]
            enabled = bool(secret.get("RotationEnabled"))
            interval = _rotation_days(secret.get("RotationRules", {}))
            last_rotated = secret.get("LastRotatedDate")
            # A never-rotated secret has held the same value since it was created.
            since = last_rotated or secret.get("CreatedDate")
            age = (ctx.now - since).days if since else None
            owner = secret.get("OwningService")
            # Service-owned secrets (RDS, Redshift, ...) are judged the same way: the
            # credential's age is the risk whoever manages it; only the fix differs.
            via = f" (managed by {owner}; change rotation through that service)" if owner else ""
            mine: list[Finding] = []
            if not enabled:
                mine.append(Finding(arn, f"Automatic rotation is disabled{via}", Severity.MEDIUM))
            else:
                if interval is not None and interval > max_days:
                    mine.append(
                        Finding(
                            arn,
                            f"Rotation interval of {interval} day(s) exceeds {max_days}{via}",
                            Severity.LOW,
                        )
                    )
                # Older than both the policy maximum and its own schedule: rotation is failing.
                if age is not None and age > max(max_days, interval or 0):
                    mine.append(
                        Finding(
                            arn,
                            f"Rotation is enabled but the secret was last rotated {age} day(s) "
                            f"ago (> {max_days}); rotation may be failing{via}",
                            Severity.MEDIUM,
                        )
                    )
            findings += mine
            resources.append(
                resource(
                    arn,
                    "AWS::SecretsManager::Secret",
                    not mine,
                    rotation_enabled=enabled,
                    rotation_days=interval,
                    last_rotated=utc_iso(last_rotated.astimezone(UTC)) if last_rotated else None,
                    days_since_rotation=age,
                    owning_service=owner,
                )
            )
        return Result(
            summary=f"{len(secrets)} secret(s); {len(findings)} rotation finding(s)",
            findings=findings,
            data={"secrets_examined": len(secrets), "resources": resources},
            status=Status.NOT_APPLICABLE if not secrets else None,
            truncated_at=ctx.params.max_items_per_check if secrets.truncated else None,
        )
