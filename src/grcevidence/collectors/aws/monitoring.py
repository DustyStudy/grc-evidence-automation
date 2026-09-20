"""Logging, monitoring and network-boundary evidence."""

from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from grcevidence.collectors.base import Collector, Context, Result, paginate, register
from grcevidence.models import Finding, Severity

_OPEN_CIDRS = {"0.0.0.0/0", "::/0"}


@register
class CloudTrail(Collector):
    id = "aws.cloudtrail"
    title = "CloudTrail multi-region logging with log-file validation"
    scope = "global"
    permissions = ("cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus")

    def collect(self, ctx: Context) -> Result:
        ct = ctx.client("cloudtrail")
        trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
        findings: list[Finding] = []
        details: list[dict[str, Any]] = []
        compliant = 0
        for t in trails:
            home = t.get("HomeRegion", ctx.region)
            regional = ctx.client("cloudtrail", home)
            logging_on = bool(regional.get_trail_status(Name=t["TrailARN"]).get("IsLogging"))
            multi = bool(t.get("IsMultiRegionTrail"))
            validation = bool(t.get("LogFileValidationEnabled"))
            details.append(
                {
                    "name": t["Name"],
                    "multi_region": multi,
                    "organization_trail": bool(t.get("IsOrganizationTrail")),
                    "logging": logging_on,
                    "log_file_validation": validation,
                    "kms_encrypted": bool(t.get("KmsKeyId")),
                    "s3_bucket": t.get("S3BucketName"),
                }
            )
            if not logging_on:
                findings.append(
                    Finding(t["Name"], "Trail exists but logging is stopped", Severity.HIGH)
                )
            if not validation:
                findings.append(
                    Finding(t["Name"], "Log-file integrity validation is disabled", Severity.MEDIUM)
                )
            if multi and logging_on and validation:
                compliant += 1
        if not trails:
            findings.append(
                Finding("account", "No CloudTrail trail is configured", Severity.CRITICAL)
            )
        elif not any(d["multi_region"] and d["logging"] for d in details):
            findings.append(
                Finding(
                    "account",
                    "No logging multi-region trail (management events may be missed in some regions)",
                    Severity.HIGH,
                )
            )
        return Result(
            summary=f"{len(trails)} trail(s); {compliant} multi-region, logging, with validation",
            findings=findings,
            data={"trails": details, "compliant_trails": compliant},
        )


@register
class ThreatDetection(Collector):
    id = "aws.threat_detection"
    title = "GuardDuty and Security Hub enablement"
    permissions = ("guardduty:ListDetectors", "guardduty:GetDetector", "securityhub:DescribeHub")

    def collect(self, ctx: Context) -> Result:
        gd = ctx.client("guardduty")
        detector_ids = gd.list_detectors().get("DetectorIds", [])
        gd_enabled = any(
            gd.get_detector(DetectorId=d).get("Status") == "ENABLED" for d in detector_ids
        )
        sh_enabled = self._securityhub_enabled(ctx)
        findings: list[Finding] = []
        if not gd_enabled:
            findings.append(
                Finding(
                    f"guardduty:{ctx.region}",
                    "GuardDuty is not enabled in this region",
                    Severity.HIGH,
                )
            )
        if ctx.params.require_securityhub and not sh_enabled:
            findings.append(
                Finding(
                    f"securityhub:{ctx.region}",
                    "Security Hub is not enabled in this region",
                    Severity.MEDIUM,
                )
            )
        return Result(
            summary=f"GuardDuty {'enabled' if gd_enabled else 'NOT enabled'}; Security Hub {'enabled' if sh_enabled else 'not enabled'}",
            findings=findings,
            data={"guardduty_enabled": gd_enabled, "securityhub_enabled": sh_enabled},
        )

    @staticmethod
    def _securityhub_enabled(ctx: Context) -> bool:
        try:
            ctx.client("securityhub").describe_hub()
            return True
        except ClientError as exc:
            if exc.response["Error"]["Code"] in {
                "InvalidAccessException",
                "ResourceNotFoundException",
            }:
                return False
            raise


@register
class ConfigRecorder(Collector):
    id = "aws.config_recorder"
    title = "AWS Config configuration recorder"
    permissions = (
        "config:DescribeConfigurationRecorders",
        "config:DescribeConfigurationRecorderStatus",
    )

    def collect(self, ctx: Context) -> Result:
        cfg = ctx.client("config")
        recorders = cfg.describe_configuration_recorders().get("ConfigurationRecorders", [])
        status = {
            s["name"]: s
            for s in cfg.describe_configuration_recorder_status().get(
                "ConfigurationRecordersStatus", []
            )
        }
        findings: list[Finding] = []
        recording = 0
        for r in recorders:
            if status.get(r["name"], {}).get("recording"):
                recording += 1
            else:
                findings.append(
                    Finding(
                        r["name"],
                        "Configuration recorder exists but is not recording",
                        Severity.HIGH,
                    )
                )
        if not recorders:
            findings.append(
                Finding(
                    f"config:{ctx.region}", "No AWS Config recorder in this region", Severity.HIGH
                )
            )
        return Result(
            summary=f"{recording}/{len(recorders)} configuration recorder(s) recording",
            findings=findings,
            data={
                "recorders": len(recorders),
                "recording": recording,
                "all_supported": [
                    bool(r.get("recordingGroup", {}).get("allSupported")) for r in recorders
                ],
            },
        )


@register
class VpcFlowLogs(Collector):
    id = "aws.vpc_flow_logs"
    title = "VPC flow logs"
    permissions = ("ec2:DescribeVpcs", "ec2:DescribeFlowLogs")

    def collect(self, ctx: Context) -> Result:
        ec2 = ctx.client("ec2")
        cap = ctx.params.max_items_per_check
        vpc_list = paginate(ec2, "describe_vpcs", "Vpcs", cap)
        vpcs = [v["VpcId"] for v in vpc_list]
        flow_logs = paginate(ec2, "describe_flow_logs", "FlowLogs", cap * 4)
        covered = {
            f["ResourceId"] for f in flow_logs if f.get("FlowLogStatus", "ACTIVE") == "ACTIVE"
        }
        missing = [v for v in vpcs if v not in covered]
        return Result(
            summary=f"{len(vpcs) - len(missing)}/{len(vpcs)} VPC(s) have an active VPC-level flow log",
            findings=[
                Finding(v, "No active flow log attached to this VPC", Severity.MEDIUM)
                for v in missing
            ],
            data={"vpcs": len(vpcs), "vpcs_without_flow_logs": len(missing)},
            truncated_at=cap if vpc_list.truncated or flow_logs.truncated else None,
        )


@register
class NetworkExposure(Collector):
    id = "aws.network_exposure"
    title = "Security groups open to the internet"
    permissions = ("ec2:DescribeSecurityGroups",)

    def collect(self, ctx: Context) -> Result:
        groups = paginate(
            ctx.client("ec2"),
            "describe_security_groups",
            "SecurityGroups",
            ctx.params.max_items_per_check,
        )
        sensitive = ctx.params.sensitive_ports
        findings: list[Finding] = []
        exposed: set[str] = set()
        for g in groups:
            label = f"{g['GroupId']} ({g.get('GroupName', '')})"
            for perm in g.get("IpPermissions", []):
                cidrs = [r["CidrIp"] for r in perm.get("IpRanges", [])] + [
                    r["CidrIpv6"] for r in perm.get("Ipv6Ranges", [])
                ]
                if not _OPEN_CIDRS.intersection(cidrs):
                    continue
                proto = perm.get("IpProtocol")
                if proto == "-1":
                    findings.append(
                        Finding(label, "Allows ALL traffic from the internet", Severity.CRITICAL)
                    )
                    exposed.add(g["GroupId"])
                elif proto in {"tcp", "6"}:
                    lo, hi = perm.get("FromPort", 0), perm.get("ToPort", 65535)
                    for port in sensitive:
                        if lo <= port <= hi:
                            findings.append(
                                Finding(
                                    label, f"Port {port}/tcp open to the internet", Severity.HIGH
                                )
                            )
                            exposed.add(g["GroupId"])
        return Result(
            summary=f"{len(groups)} security group(s) examined; {len(exposed)} expose sensitive ports to the internet",
            findings=findings,
            data={
                "security_groups": len(groups),
                "exposed_groups": len(exposed),
                "sensitive_ports": list(sensitive),
            },
            truncated_at=ctx.params.max_items_per_check if groups.truncated else None,
        )
