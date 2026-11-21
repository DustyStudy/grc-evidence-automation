"""AWS Config rule compliance and evaluation freshness, ingested as evidence."""

from __future__ import annotations

from collections import Counter
from typing import Any

from grcevidence.collectors.base import Collector, Context, Result, paginate, register, resource
from grcevidence.models import Finding, Severity, Status, utc_iso


@register
class ConfigRules(Collector):
    id = "aws.config_rules"
    title = "AWS Config rule compliance and evaluation status"
    permissions = (
        "config:DescribeConfigRules",
        "config:DescribeComplianceByConfigRule",
        "config:DescribeConfigRuleEvaluationStatus",
    )

    def collect(self, ctx: Context) -> Result:
        cfg = ctx.client("config")
        cap = ctx.params.max_items_per_check
        rules = paginate(cfg, "describe_config_rules", "ConfigRules", cap)
        if not rules:
            return Result(
                summary="No AWS Config rules in this region", status=Status.NOT_APPLICABLE
            )
        compliance = paginate(
            cfg, "describe_compliance_by_config_rule", "ComplianceByConfigRules", cap
        )
        # Rule-level freshness instead of per-resource history (GetComplianceDetailsByConfigRule
        # is one call per rule and page of resources); the contributor count gives the size.
        statuses = paginate(
            cfg, "describe_config_rule_evaluation_status", "ConfigRulesEvaluationStatus", cap
        )
        by_rule = {c["ConfigRuleName"]: c.get("Compliance", {}) for c in compliance}
        evals = {s["ConfigRuleName"]: s for s in statuses}

        findings: list[Finding] = []
        resources: list[dict[str, Any]] = []
        counts: Counter[str] = Counter()
        for rule in rules:
            name = rule["ConfigRuleName"]
            comp = by_rule.get(name, {})
            # A rule Config has not reported on yet has no data, which is not a pass.
            ctype = comp.get("ComplianceType", "INSUFFICIENT_DATA")
            counts[ctype] += 1
            contributors = comp.get("ComplianceContributorCount", {})
            ev = evals.get(name, {})
            ok, bad = ev.get("LastSuccessfulEvaluationTime"), ev.get("LastFailedEvaluationTime")
            eval_failed = bad is not None and (ok is None or bad > ok)
            before = len(findings)
            if ctype == "NON_COMPLIANT":
                count = contributors.get("CappedCount", 0)
                more = "+" if contributors.get("CapExceeded") else ""
                findings.append(
                    Finding(
                        name,
                        f"Config rule is NON_COMPLIANT on {count}{more} resource(s)",
                        Severity.MEDIUM,
                    )
                )
            elif ctype == "INSUFFICIENT_DATA":
                findings.append(
                    Finding(name, "Config rule has insufficient data to evaluate", Severity.LOW)
                )
            if eval_failed:
                findings.append(
                    Finding(
                        name,
                        f"Last evaluation of the Config rule failed ({ev.get('LastErrorCode', '')})",
                        Severity.MEDIUM,
                    )
                )
            source = rule.get("Source", {})
            resources.append(
                resource(
                    rule.get("ConfigRuleArn", name),
                    "AWS::Config::ConfigRule",
                    len(findings) == before,
                    name=name,
                    owner=source.get("Owner"),
                    source_identifier=source.get("SourceIdentifier"),
                    state=rule.get("ConfigRuleState"),
                    compliance=ctype,
                    non_compliant_resources=contributors.get("CappedCount"),
                    non_compliant_cap_exceeded=contributors.get("CapExceeded"),
                    last_successful_evaluation=ok and utc_iso(ok),
                    last_failed_evaluation=bad and utc_iso(bad),
                    first_evaluation_started=ev.get("FirstEvaluationStarted"),
                )
            )
        truncated = rules.truncated or compliance.truncated or statuses.truncated
        return Result(
            summary=(
                f"{len(rules)} Config rule(s): {counts['COMPLIANT']} compliant, "
                f"{counts['NON_COMPLIANT']} non-compliant, "
                f"{counts['INSUFFICIENT_DATA']} insufficient data, "
                f"{counts['NOT_APPLICABLE']} not applicable"
            ),
            findings=findings,
            data={"compliance_counts": dict(counts), "resources": resources},
            truncated_at=cap if truncated else None,
        )
