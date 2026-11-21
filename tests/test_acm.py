"""aws.acm_certificates tests.

moto models ListCertificates with NotAfter/InUse/Type/RenewalEligibility for imported
certificates, so it covers the listing, key-type filter, in-use and cap paths. moto ties
certificate validity to the real clock, so those tests set ctx.now relative to it. Fields
moto can't produce (EXPIRED status, AMAZON_ISSUED + ELIGIBLE) use a botocore Stubber.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import boto3
import pytest
from botocore.stub import Stubber
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from moto.acm.models import acm_backends

from grcevidence.collectors.aws.acm import _ALL_KEY_TYPES, _ALL_ORIGINS, AcmCertificates
from grcevidence.collectors.base import Context, Parameters
from grcevidence.models import Severity, Status
from tests.conftest import ACCOUNT, NOW

ACM = "AWS::CertificateManager::Certificate"


def _import_cert(acm, domain: str, valid_days: int) -> str:
    """Import a self-signed EC P-256 certificate (not returned by ListCertificates' default
    RSA-only filter) that expires ``valid_days`` from now."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=valid_days))
        .sign(key, hashes.SHA256())
    )
    return acm.import_certificate(
        Certificate=cert.public_bytes(serialization.Encoding.PEM),
        PrivateKey=key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )["CertificateArn"]


def _ctx(session, now: datetime, **params) -> Context:
    return Context(ACCOUNT, "us-east-1", session, Parameters(**params), now)


def test_no_certificates_is_not_applicable(make_ctx):
    ev = AcmCertificates().execute(make_ctx())
    assert ev.status == Status.NOT_APPLICABLE and ev.data["resources"] == []


def test_expiring_certificates_flagged_by_use(session):
    acm = session.client("acm")
    soon = _import_cert(acm, "soon.example.com", 10)
    busy = _import_cert(acm, "busy.example.com", 10)
    fine = _import_cert(acm, "fine.example.com", 200)
    acm_backends[ACCOUNT]["us-east-1"].set_certificate_in_use_by(busy, "my-alb")

    ev = AcmCertificates().execute(_ctx(session, datetime.now(UTC)))
    assert ev.status == Status.FAIL
    sev = {f.resource: f.severity for f in ev.findings}
    assert sev == {soon: Severity.MEDIUM, busy: Severity.HIGH}
    res = {r["id"]: r for r in ev.data["resources"]}
    assert {r["type"] for r in res.values()} == {ACM}
    assert res[fine]["compliant"] and not res[soon]["compliant"]
    attrs = res[busy]["attributes"]
    assert attrs["in_use"] is True and attrs["type"] == "IMPORTED"
    assert attrs["domain_name"] == "busy.example.com" and attrs["days_remaining"] in (8, 9)
    assert attrs["status"] == "ISSUED" and attrs["renewal_eligibility"] == "INELIGIBLE"
    assert attrs["not_after"].endswith("+00:00")


def test_threshold_is_a_parameter(session):
    _import_cert(session.client("acm"), "soon.example.com", 10)
    ev = AcmCertificates().execute(
        _ctx(session, datetime.now(UTC), min_certificate_days_remaining=5)
    )
    assert ev.status == Status.PASS


def test_past_not_after_counts_as_expired_even_if_status_lags(session):
    arn = _import_cert(session.client("acm"), "old.example.com", 10)
    ev = AcmCertificates().execute(_ctx(session, datetime.now(UTC) + timedelta(days=30)))
    (finding,) = ev.findings
    assert finding.resource == arn and finding.severity == Severity.LOW
    assert (
        "expired" in finding.message and ev.data["resources"][0]["attributes"]["days_remaining"] < 0
    )


def test_cap_marks_record_incomplete(session):
    acm = session.client("acm")
    _import_cert(acm, "a.example.com", 200)
    _import_cert(acm, "b.example.com", 200)
    ev = AcmCertificates().execute(_ctx(session, datetime.now(UTC), max_items_per_check=1))
    assert ev.status == Status.ERROR and ev.data["truncated"]
    assert len(ev.data["resources"]) == 1


def _summary(**overrides):
    return {
        "CertificateArn": "arn:aws:acm:us-east-1:123456789012:certificate/x",
        "DomainName": "x.example.com",
        "Status": "ISSUED",
        "Type": "AMAZON_ISSUED",
        "InUse": True,
        "RenewalEligibility": "ELIGIBLE",
        "NotAfter": NOW + timedelta(days=12),
        **overrides,
    }


@pytest.mark.parametrize(
    ("summary", "severity", "text"),
    [
        (_summary(), Severity.HIGH, "managed renewal has not completed"),
        (_summary(Status="EXPIRED", NotAfter=NOW - timedelta(days=3)), Severity.HIGH, "in use"),
    ],
)
def test_stubbed_amazon_issued_and_expired(summary, severity, text):
    client = boto3.client("acm", region_name="us-east-1")
    stub = Stubber(client)
    stub.add_response(
        "list_certificates",
        {"CertificateSummaryList": [summary]},
        {
            "CertificateStatuses": ["ISSUED", "EXPIRED"],
            "CertificateKeyPairOrigins": _ALL_ORIGINS,
            "Includes": {"keyTypes": _ALL_KEY_TYPES},
        },
    )

    class _Session:
        def client(self, *_args, **_kwargs):
            return client

    with stub:
        ev = AcmCertificates().execute(Context(ACCOUNT, "us-east-1", _Session(), Parameters(), NOW))
    (finding,) = ev.findings
    assert finding.severity == severity and text in finding.message
