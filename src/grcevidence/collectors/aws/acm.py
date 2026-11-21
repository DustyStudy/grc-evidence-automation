"""Certificate evidence: ACM certificate expiry."""

from __future__ import annotations

from datetime import UTC

from grcevidence.collectors.base import Collector, Context, Result, paginate, register, resource
from grcevidence.models import Finding, Severity, Status, utc_iso

# ListCertificates returns only RSA_1024/RSA_2048 and non-ACME certificates unless asked.
_ALL_KEY_TYPES = [
    "RSA_1024",
    "RSA_2048",
    "RSA_3072",
    "RSA_4096",
    "EC_prime256v1",
    "EC_secp384r1",
    "EC_secp521r1",
]
_ALL_ORIGINS = ["AWS_MANAGED", "ACME", "CUSTOMER_PROVIDED"]


@register
class AcmCertificates(Collector):
    id = "aws.acm_certificates"
    title = "ACM certificate expiry"
    permissions = ("acm:ListCertificates",)

    def collect(self, ctx: Context) -> Result:
        min_days = ctx.params.min_certificate_days_remaining
        # The summary carries NotAfter, InUse, Type and RenewalEligibility, so no per-cert
        # DescribeCertificate call is needed.
        certs = paginate(
            ctx.client("acm"),
            "list_certificates",
            "CertificateSummaryList",
            ctx.params.max_items_per_check,
            CertificateStatuses=["ISSUED", "EXPIRED"],
            CertificateKeyPairOrigins=_ALL_ORIGINS,
            Includes={"keyTypes": _ALL_KEY_TYPES},
        )
        findings: list[Finding] = []
        resources = []
        for cert in certs:
            arn = cert["CertificateArn"]
            not_after = cert["NotAfter"].astimezone(UTC)
            days = (not_after - ctx.now).days
            in_use = bool(cert.get("InUse"))
            finding = None
            if cert["Status"] == "EXPIRED" or days < 0:
                finding = Finding(
                    arn,
                    f"Certificate expired on {not_after.date()}"
                    + (" and is still in use" if in_use else " (not in use; delete it)"),
                    Severity.HIGH if in_use else Severity.LOW,
                )
            elif days < min_days:
                note = ""
                if cert.get("Type") == "AMAZON_ISSUED" and cert.get("RenewalEligibility") == (
                    "ELIGIBLE"
                ):
                    note = "; ACM managed renewal has not completed (check domain validation)"
                finding = Finding(
                    arn,
                    f"Certificate expires in {days} day(s) (< {min_days})"
                    + (", in use" if in_use else ", not in use")
                    + note,
                    Severity.HIGH if in_use else Severity.MEDIUM,
                )
            if finding:
                findings.append(finding)
            resources.append(
                resource(
                    arn,
                    "AWS::CertificateManager::Certificate",
                    finding is None,
                    domain_name=cert.get("DomainName"),
                    type=cert.get("Type"),
                    status=cert["Status"],
                    not_after=utc_iso(not_after),
                    days_remaining=days,
                    in_use=in_use,
                    renewal_eligibility=cert.get("RenewalEligibility"),
                )
            )
        return Result(
            summary=f"{len(certs)} issued/expired certificate(s); {len(findings)} expiring "
            f"within {min_days} day(s) or expired",
            findings=findings,
            data={"certificates_examined": len(certs), "resources": resources},
            status=Status.NOT_APPLICABLE if not certs else None,
            truncated_at=ctx.params.max_items_per_check if certs.truncated else None,
        )
