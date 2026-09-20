"""GCP collectors (optional, install with ``pip install "grc-evidence-automation[gcp]"``).

Experimental: unit-tested against fake clients that mirror the documented
``google-cloud-storage`` and ``google-cloud-compute`` object shapes, but not
exercised against a live GCP project by this repo's CI. Credentials come from
Application Default Credentials (e.g. Workload Identity Federation); nothing
here reads or stores a service-account key.
"""

from __future__ import annotations

from typing import Any

from grcevidence.collectors.base import Collector, Context, Result, register
from grcevidence.models import Finding, Severity


class _DefaultClients:
    """Lazily builds real Google clients; tests inject a fake with the same two methods."""

    def __init__(self, project: str) -> None:
        self.project = project

    def storage(self) -> Any:
        from google.cloud import storage

        return storage.Client(project=self.project)

    def firewalls(self) -> Any:
        from google.cloud import compute_v1

        return compute_v1.FirewallsClient()


def _clients(ctx: Context) -> Any:
    return ctx.gcp_clients or _DefaultClients(ctx.gcp_project or "")


@register
class GcsBuckets(Collector):
    id = "gcp.storage_buckets"
    provider = "gcp"
    title = "Cloud Storage uniform access and public-access prevention"
    scope = "global"
    permissions = ("storage.buckets.list", "storage.buckets.get")

    def collect(self, ctx: Context) -> Result:
        buckets = list(_clients(ctx).storage().list_buckets())[: ctx.params.max_items_per_check]
        findings: list[Finding] = []
        for b in buckets:
            iam = b.iam_configuration
            if not iam.uniform_bucket_level_access_enabled:
                findings.append(
                    Finding(
                        b.name,
                        "Uniform bucket-level access is disabled (legacy ACLs in effect)",
                        Severity.MEDIUM,
                    )
                )
            if str(iam.public_access_prevention or "").lower() != "enforced":
                findings.append(
                    Finding(b.name, "Public access prevention is not enforced", Severity.HIGH)
                )
        return Result(
            summary=f"{len(buckets)} bucket(s) examined; {len(findings)} finding(s)",
            findings=findings,
            data={"buckets_examined": len(buckets)},
        )


@register
class GcpFirewallExposure(Collector):
    id = "gcp.firewall_exposure"
    provider = "gcp"
    title = "VPC firewall rules open to the internet"
    scope = "global"
    permissions = ("compute.firewalls.list",)

    def collect(self, ctx: Context) -> Result:
        rules = list(_clients(ctx).firewalls().list(project=ctx.gcp_project))
        sensitive = {str(p) for p in ctx.params.sensitive_ports}
        findings: list[Finding] = []
        for fw in rules:
            if (
                getattr(fw, "disabled", False)
                or str(getattr(fw, "direction", "INGRESS")).upper() != "INGRESS"
            ):
                continue
            if "0.0.0.0/0" not in list(getattr(fw, "source_ranges", [])):
                continue
            for allowed in getattr(fw, "allowed", []):
                proto = str(
                    getattr(allowed, "I_p_protocol", None) or getattr(allowed, "ip_protocol", "")
                ).lower()
                ports = [str(p) for p in getattr(allowed, "ports", [])]
                if proto == "all":
                    findings.append(
                        Finding(fw.name, "Allows ALL protocols from 0.0.0.0/0", Severity.CRITICAL)
                    )
                elif proto == "tcp" and (not ports or any(_port_hits(p, sensitive) for p in ports)):
                    findings.append(
                        Finding(
                            fw.name,
                            "Allows sensitive tcp ports (or all ports) from 0.0.0.0/0",
                            Severity.HIGH,
                        )
                    )
        return Result(
            summary=f"{len(rules)} firewall rule(s) examined; {len(findings)} finding(s)",
            findings=findings,
            data={"firewall_rules": len(rules), "sensitive_ports": sorted(sensitive)},
        )


def _port_hits(spec: str, sensitive: set[str]) -> bool:
    if "-" in spec:
        lo, hi = spec.split("-", 1)
        return any(int(lo) <= int(p) <= int(hi) for p in sensitive)
    return spec in sensitive
