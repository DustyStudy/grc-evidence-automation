"""GCP collectors (optional, install with ``pip install "grc-evidence-automation[gcp]"``).

Experimental: unit-tested against fake clients that mirror the documented
``google-cloud-storage`` and ``google-cloud-compute`` object shapes, but not
exercised against a live GCP project by this repo's CI. Credentials come from
Application Default Credentials (e.g. Workload Identity Federation); nothing
here reads or stores a service-account key.
"""

from __future__ import annotations

from typing import Any

from grcevidence.collectors.base import Collector, Context, Result, register, resource
from grcevidence.collectors.cidr import internet_ranges
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
        cap = ctx.params.max_items_per_check
        all_buckets = list(_clients(ctx).storage().list_buckets())
        buckets = all_buckets[:cap]
        findings: list[Finding] = []
        resources: list[dict[str, Any]] = []
        for b in buckets:
            iam = b.iam_configuration
            ubla = bool(iam.uniform_bucket_level_access_enabled)
            pap = str(iam.public_access_prevention or "").lower() == "enforced"
            if not ubla:
                findings.append(
                    Finding(
                        b.name,
                        "Uniform bucket-level access is disabled (legacy ACLs in effect)",
                        Severity.MEDIUM,
                    )
                )
            if not pap:
                findings.append(
                    Finding(b.name, "Public access prevention is not enforced", Severity.HIGH)
                )
            resources.append(
                resource(
                    b.name,
                    "storage.googleapis.com/Bucket",
                    ubla and pap,
                    uniform_bucket_level_access=ubla,
                    public_access_prevention_enforced=pap,
                )
            )
        return Result(
            summary=f"{len(buckets)} bucket(s) examined; {len(findings)} finding(s)",
            findings=findings,
            data={"buckets_examined": len(buckets), "resources": resources},
            truncated_at=cap if len(all_buckets) > cap else None,
        )


@register
class GcpFirewallExposure(Collector):
    id = "gcp.firewall_exposure"
    provider = "gcp"
    title = "VPC firewall rules open to the internet"
    scope = "global"
    permissions = ("compute.firewalls.list",)

    def collect(self, ctx: Context) -> Result:
        cap = ctx.params.max_items_per_check
        all_rules = list(_clients(ctx).firewalls().list(project=ctx.gcp_project))
        rules = all_rules[:cap]
        sensitive = {str(p) for p in ctx.params.sensitive_ports}
        findings: list[Finding] = []
        resources: list[dict[str, Any]] = []
        for fw in rules:
            # "0.0.0.0/0" and/or "::/0", named in the finding text, when the source ranges
            # together cover the whole family (also "0.0.0.0/1" + "128.0.0.0/1", "0::/0").
            src = " and ".join(internet_ranges(getattr(fw, "source_ranges", [])))
            open_to_internet = (
                not getattr(fw, "disabled", False)
                and str(getattr(fw, "direction", "INGRESS")).upper() == "INGRESS"
                and bool(src)
            )
            all_protocols = sensitive_tcp = False
            for allowed in getattr(fw, "allowed", []) if open_to_internet else []:
                proto = str(
                    getattr(allowed, "I_p_protocol", None) or getattr(allowed, "ip_protocol", "")
                ).lower()  # GCP also accepts the IANA number: "6" is tcp
                ports = [str(p) for p in getattr(allowed, "ports", [])]
                if proto == "all":
                    all_protocols = True
                    findings.append(
                        Finding(fw.name, f"Allows ALL protocols from {src}", Severity.CRITICAL)
                    )
                elif proto in ("tcp", "6") and (
                    not ports or any(_port_hits(p, sensitive) for p in ports)
                ):
                    sensitive_tcp = True
                    findings.append(
                        Finding(
                            fw.name,
                            f"Allows sensitive tcp ports (or all ports) from {src}",
                            Severity.HIGH,
                        )
                    )
            resources.append(
                resource(
                    fw.name,
                    "compute.googleapis.com/Firewall",
                    not (all_protocols or sensitive_tcp),
                    open_to_internet=open_to_internet,
                    all_protocols=all_protocols,
                    sensitive_tcp_open=sensitive_tcp,
                )
            )
        return Result(
            summary=f"{len(rules)} firewall rule(s) examined; {len(findings)} finding(s)",
            findings=findings,
            data={
                "firewall_rules": len(rules),
                "sensitive_ports": sorted(sensitive),
                "resources": resources,
            },
            truncated_at=cap if len(all_rules) > cap else None,
        )


def _port_hits(spec: str, sensitive: set[str]) -> bool:
    if "-" in spec:
        lo, hi = spec.split("-", 1)
        return any(int(lo) <= int(p) <= int(hi) for p in sensitive)
    return spec in sensitive
