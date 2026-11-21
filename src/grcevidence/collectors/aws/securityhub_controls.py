"""Security Hub CSPM control results, ingested as evidence instead of re-implementing the checks."""

from __future__ import annotations

from collections import Counter
from typing import Any

from botocore.exceptions import ClientError

from grcevidence.collectors.base import Collector, Context, Result, paginate, register, resource
from grcevidence.models import Finding, Severity, Status

_NOT_ENABLED = {"InvalidAccessException", "ResourceNotFoundException"}
_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFORMATIONAL": Severity.LOW,
}
_RANK = ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


@register
class SecurityHubControls(Collector):
    id = "aws.securityhub_controls"
    title = "Security Hub CSPM control results per enabled standard"
    permissions = (
        "securityhub:DescribeHub",
        "securityhub:GetEnabledStandards",
        "securityhub:DescribeStandards",
        "securityhub:GetFindings",
    )

    def collect(self, ctx: Context) -> Result:
        sh = ctx.client("securityhub")
        try:
            sh.describe_hub()
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in _NOT_ENABLED:
                raise
            return Result(
                summary="Security Hub CSPM is not enabled in this region; no control results",
                status=Status.NOT_APPLICABLE,
            )
        subs = paginate(sh, "get_enabled_standards", "StandardsSubscriptions")
        if not subs:
            return Result(
                summary="Security Hub CSPM has no enabled standards in this region",
                status=Status.NOT_APPLICABLE,
            )
        names = {
            s["StandardsArn"]: s.get("Name", "")
            for s in paginate(sh, "describe_standards", "Standards")
        }
        # Control status is derived the way Security Hub derives it: active, non-suppressed
        # control findings, here limited to this account and region (an administrator or
        # aggregation-region hub also returns member-account and linked-region findings).
        # One finding per control per resource, so the cap on findings is wider than the cap on
        # resources (controls); otherwise most real accounts would always read as incomplete.
        cap = ctx.params.max_items_per_check * 20
        raw = paginate(
            sh,
            "get_findings",
            "Findings",
            cap,
            Filters={
                "AwsAccountId": [{"Value": ctx.account, "Comparison": "EQUALS"}],
                "Region": [{"Value": ctx.region, "Comparison": "EQUALS"}],
                "ProductName": [{"Value": "Security Hub", "Comparison": "EQUALS"}],
                "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
                "WorkflowStatus": [{"Value": "SUPPRESSED", "Comparison": "NOT_EQUALS"}],
                "ComplianceStatus": [
                    {"Value": v, "Comparison": "EQUALS"}
                    for v in ("FAILED", "PASSED", "WARNING", "NOT_AVAILABLE")
                ],
            },
        )
        controls: dict[str, dict[str, Any]] = {}
        for f in raw:
            comp = f.get("Compliance", {})
            cid = comp.get("SecurityControlId")
            if not cid:
                continue  # a finding without a control id is not a control result
            c = controls.setdefault(
                cid,
                {"title": f.get("Title", ""), "severity": "INFORMATIONAL", "standards": set()},
            )
            label = f.get("Severity", {}).get("Label", "INFORMATIONAL")
            if label in _RANK and _RANK.index(label) > _RANK.index(c["severity"]):
                c["severity"] = label
            c["standards"].update(s["StandardsId"] for s in comp.get("AssociatedStandards", []))
            # Count resources, not findings: with consolidated findings off there is one
            # finding per standard for the same resource.
            res_id = (f.get("Resources") or [{}])[0].get("Id", f.get("Id", ""))
            c.setdefault(comp.get("Status", "NOT_AVAILABLE"), set()).add(res_id)

        findings: list[Finding] = []
        resources: list[dict[str, Any]] = []
        for sub in subs:
            ready = sub.get("StandardsStatus") == "READY"
            name = names.get(sub["StandardsArn"], "")
            if not ready:
                findings.append(
                    Finding(
                        sub["StandardsArn"],
                        f"Standard is {sub.get('StandardsStatus')}, not READY; its controls may "
                        "not be evaluated",
                        Severity.MEDIUM,
                    )
                )
            resources.append(
                resource(
                    sub["StandardsSubscriptionArn"],
                    "AWS::SecurityHub::Standard",
                    ready,
                    standards_arn=sub["StandardsArn"],
                    name=name,
                    status=sub.get("StandardsStatus"),
                )
            )
        counts: Counter[str] = Counter()
        for cid, c in sorted(controls.items()):
            if c.get("FAILED"):
                status = "FAILED"
                findings.append(
                    Finding(
                        cid,
                        f"Security Hub control failed on {len(c['FAILED'])} resource(s): "
                        f"{c['title']}",
                        _SEVERITY.get(c["severity"], Severity.LOW),
                    )
                )
            elif c.get("WARNING") or c.get("NOT_AVAILABLE"):
                status = "UNKNOWN"
                findings.append(
                    Finding(
                        cid,
                        f"Security Hub could not evaluate this control (WARNING/NOT_AVAILABLE): "
                        f"{c['title']}",
                        Severity.LOW,
                    )
                )
            else:
                status = "PASSED"
            counts[status] += 1
            resources.append(
                resource(
                    cid,
                    "AWS::SecurityHub::SecurityControl",
                    status == "PASSED",
                    control_id=cid,
                    title=c["title"],
                    severity=c["severity"],
                    standards=sorted(c["standards"]),
                    failed_resources=len(c.get("FAILED", ())),
                    passed_resources=len(c.get("PASSED", ())),
                    compliance_status=status,
                )
            )
        standards = [
            {
                "arn": s["StandardsArn"],
                "name": names.get(s["StandardsArn"], ""),
                "status": s.get("StandardsStatus"),
            }
            for s in subs
        ]
        summary = (
            f"{len(subs)} standard(s); {len(controls)} control(s) with results: "
            f"{counts['FAILED']} failed, {counts['PASSED']} passed, {counts['UNKNOWN']} unknown"
        )
        return Result(
            summary=summary,
            findings=findings,
            data={
                "standards": standards,
                "control_status_counts": dict(counts),
                "findings_examined": len(raw),
                "resources": resources,
            },
            # No control findings yet (new hub, all suppressed): nothing to judge, not a pass.
            status=None if controls or findings else Status.NOT_APPLICABLE,
            truncated_at=cap if raw.truncated else None,
        )
