"""Logging, monitoring and network-boundary evidence."""

from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from grcevidence.collectors.base import Collector, Context, Result, paginate, register, resource
from grcevidence.collectors.cidr import internet_ranges
from grcevidence.models import Finding, Severity

_PROTOCOLS = {"tcp": "tcp", "6": "tcp", "udp": "udp", "17": "udp"}


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
        resources: list[dict[str, Any]] = []
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
            resources.append(
                resource(
                    t["Name"],
                    "AWS::CloudTrail::Trail",
                    logging_on and validation,
                    multi_region=multi,
                    logging=logging_on,
                    log_file_validation=validation,
                )
            )
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
            data={"trails": details, "compliant_trails": compliant, "resources": resources},
        )


@register
class ThreatDetection(Collector):
    id = "aws.threat_detection"
    title = "GuardDuty and Security Hub enablement"
    permissions = ("guardduty:ListDetectors", "guardduty:GetDetector", "securityhub:DescribeHub")

    def collect(self, ctx: Context) -> Result:
        gd = ctx.client("guardduty")
        detector_ids = gd.list_detectors().get("DetectorIds", [])
        resources: list[dict[str, Any]] = []
        for d in detector_ids:
            enabled = gd.get_detector(DetectorId=d).get("Status") == "ENABLED"
            resources.append(resource(d, "AWS::GuardDuty::Detector", enabled, enabled=enabled))
        gd_enabled = any(r["compliant"] for r in resources)
        hub_arn = self._securityhub_hub(ctx)
        sh_enabled = hub_arn is not None
        if hub_arn:
            resources.append(resource(hub_arn, "AWS::SecurityHub::Hub", True, enabled=True))
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
            data={
                "guardduty_enabled": gd_enabled,
                "securityhub_enabled": sh_enabled,
                "resources": resources,
            },
        )

    @staticmethod
    def _securityhub_hub(ctx: Context) -> str | None:
        """The region's Security Hub ARN, or None when Security Hub is not enabled."""
        try:
            return str(ctx.client("securityhub").describe_hub()["HubArn"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] in {
                "InvalidAccessException",
                "ResourceNotFoundException",
            }:
                return None
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
        resources: list[dict[str, Any]] = []
        recording = 0
        for r in recorders:
            is_recording = bool(status.get(r["name"], {}).get("recording"))
            resources.append(
                resource(
                    r["name"],
                    "AWS::Config::ConfigurationRecorder",
                    is_recording,
                    recording=is_recording,
                )
            )
            if is_recording:
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
                "resources": resources,
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
        # REJECT-only logs miss accepted traffic, and a log that fails delivery records nothing.
        covered = {
            f["ResourceId"]
            for f in flow_logs
            if f.get("FlowLogStatus", "ACTIVE") == "ACTIVE"
            and f.get("DeliverLogsStatus") == "SUCCESS"
            and f.get("TrafficType") in {"ALL", "ACCEPT"}
        }
        missing = [v for v in vpcs if v not in covered]
        return Result(
            summary=f"{len(vpcs) - len(missing)}/{len(vpcs)} VPC(s) have an active VPC-level flow log",
            findings=[
                Finding(
                    v,
                    "No active flow log delivering ALL or ACCEPT traffic is attached to this VPC",
                    Severity.MEDIUM,
                )
                for v in missing
            ],
            data={
                "vpcs": len(vpcs),
                "vpcs_without_flow_logs": len(missing),
                "resources": [
                    resource(v, "AWS::EC2::VPC", v in covered, flow_log_active=v in covered)
                    for v in vpcs
                ],
            },
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
        resources: list[dict[str, Any]] = []
        exposed: set[str] = set()
        for g in groups:
            label = f"{g['GroupId']} ({g.get('GroupName', '')})"
            # Ranges are pooled across the group's rules before judging, so an "any" source
            # split over several CIDRs or several rules is still seen as internet-open.
            any_proto: list[str] = []
            rules: list[tuple[str, int, int, list[str]]] = []
            for perm in g.get("IpPermissions", []):
                cidrs = [r["CidrIp"] for r in perm.get("IpRanges", [])] + [
                    r["CidrIpv6"] for r in perm.get("Ipv6Ranges", [])
                ]
                proto = perm.get("IpProtocol")
                if proto == "-1":
                    any_proto += cidrs
                elif proto in _PROTOCOLS:
                    rules.append(
                        (
                            _PROTOCOLS[proto],
                            perm.get("FromPort", 0),
                            perm.get("ToPort", 65535),
                            cidrs,
                        )
                    )
            all_traffic = bool(internet_ranges(any_proto))
            if all_traffic:
                findings.append(
                    Finding(label, "Allows ALL traffic from the internet", Severity.CRITICAL)
                )
                any_proto = []  # already reported; ports below are judged on tcp/udp rules alone
            open_ports: set[int] = set()
            for proto in ("tcp", "udp"):  # never pooled together: half tcp + half udp is not open
                hit = sorted(
                    port
                    for port in sensitive
                    if internet_ranges(
                        any_proto
                        + [
                            c
                            for p, lo, hi, cidrs in rules
                            if p == proto and lo <= port <= hi
                            for c in cidrs
                        ]
                    )
                )
                findings += [
                    Finding(label, f"Port {port}/{proto} open to the internet", Severity.HIGH)
                    for port in hit
                ]
                open_ports.update(hit)
            if all_traffic or open_ports:
                exposed.add(g["GroupId"])
            resources.append(
                resource(
                    g["GroupId"],
                    "AWS::EC2::SecurityGroup",
                    g["GroupId"] not in exposed,
                    open_to_internet_ports=sorted(open_ports),
                    all_traffic=all_traffic,
                )
            )
        return Result(
            summary=f"{len(groups)} security group(s) examined; {len(exposed)} expose sensitive ports to the internet",
            findings=findings,
            data={
                "security_groups": len(groups),
                "exposed_groups": len(exposed),
                "sensitive_ports": list(sensitive),
                "resources": resources,
            },
            truncated_at=ctx.params.max_items_per_check if groups.truncated else None,
        )
