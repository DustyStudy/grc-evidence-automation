"""EKS evidence: API endpoint exposure, control-plane audit logging and secrets encryption."""

from __future__ import annotations

from grcevidence.collectors.base import Collector, Context, Result, paginate, register, resource
from grcevidence.models import Finding, Severity, Status

REQUIRED_LOG_TYPES = ("api", "audit", "authenticator")
_ANYWHERE = {"0.0.0.0/0", "::/0"}


@register
class EksSecurity(Collector):
    id = "aws.eks_security"
    title = "EKS endpoint exposure, control-plane logging and secrets encryption"
    permissions = ("eks:ListClusters", "eks:DescribeCluster")

    def collect(self, ctx: Context) -> Result:
        eks = ctx.client("eks")
        limit = ctx.params.max_items_per_check
        names = paginate(eks, "list_clusters", "clusters", limit)
        findings: list[Finding] = []
        resources = []
        for name in names:
            cluster = eks.describe_cluster(name=name)["cluster"]
            vpc = cluster.get("resourcesVpcConfig", {})
            # Absent fields mean the AWS defaults: a public endpoint open to 0.0.0.0/0.
            public = vpc.get("endpointPublicAccess", True)
            cidrs = sorted(vpc.get("publicAccessCidrs", ["0.0.0.0/0"])) if public else []
            logs = sorted(
                {
                    t
                    for entry in cluster.get("logging", {}).get("clusterLogging", [])
                    if entry.get("enabled")
                    for t in entry.get("types", [])
                }
            )
            missing = [t for t in REQUIRED_LOG_TYPES if t not in logs]
            secrets = any(
                "secrets" in e.get("resources", []) for e in cluster.get("encryptionConfig") or []
            )
            own: list[Finding] = []
            # A public endpoint limited to allow-listed CIDRs (plus IAM authentication) is a
            # supported hardening, so only an open-to-anywhere endpoint is flagged; the CIDRs are
            # recorded for review either way.
            if _ANYWHERE.intersection(cidrs):
                own.append(
                    Finding(name, "API endpoint is publicly reachable from anywhere", Severity.HIGH)
                )
            if missing:
                own.append(
                    Finding(
                        name,
                        f"Control-plane logging is missing: {', '.join(missing)}",
                        Severity.MEDIUM,
                    )
                )
            if not secrets:
                own.append(
                    Finding(
                        name,
                        "Kubernetes secrets are not envelope-encrypted with KMS",
                        Severity.MEDIUM,
                    )
                )
            findings += own
            resources.append(
                resource(
                    name,
                    "AWS::EKS::Cluster",
                    not own,
                    endpoint_public_access=public,
                    endpoint_private_access=bool(vpc.get("endpointPrivateAccess")),
                    public_access_cidrs=cidrs,
                    enabled_log_types=logs,
                    secrets_encrypted=secrets,
                )
            )
        return Result(
            summary=(
                f"{len(resources)} EKS cluster(s) examined; {len(findings)} finding(s)"
                if resources
                else "No EKS clusters in this region"
            ),
            findings=findings,
            data={"resources": resources},
            status=Status.NOT_APPLICABLE if not resources else None,
            truncated_at=limit if names.truncated else None,
        )
