"""aws.eks_security tests, all against moto's EKS model (its DescribeCluster returns
resourcesVpcConfig, logging and encryptionConfig; it omits endpointPublicAccess when unset,
which the collector reads as the AWS default of a public endpoint open to 0.0.0.0/0)."""

from __future__ import annotations

from grcevidence.collectors.aws.eks import EksSecurity
from grcevidence.models import Severity, Status

ROLE = "arn:aws:iam::123456789012:role/eks"
SUBNETS = {"subnetIds": ["subnet-1"]}


def _cluster(session, name, vpc=None, logs=None, secrets=True):
    kwargs = {}
    if logs is not None:
        kwargs["logging"] = {"clusterLogging": [{"types": logs, "enabled": True}]}
    if secrets:
        key = "arn:aws:kms:us-east-1:123456789012:key/k"
        kwargs["encryptionConfig"] = [{"resources": ["secrets"], "provider": {"keyArn": key}}]
    session.client("eks").create_cluster(
        name=name, roleArn=ROLE, resourcesVpcConfig={**SUBNETS, **(vpc or {})}, **kwargs
    )


def test_no_clusters_is_not_applicable(make_ctx):
    ev = EksSecurity().execute(make_ctx())
    assert ev.status == Status.NOT_APPLICABLE and ev.data["resources"] == []


def test_default_cluster_is_open_unlogged_and_unencrypted(make_ctx, session):
    _cluster(session, "loose", secrets=False)
    ev = EksSecurity().execute(make_ctx())
    assert ev.status == Status.FAIL
    assert sorted(f.severity for f in ev.findings) == sorted(
        [Severity.HIGH, Severity.MEDIUM, Severity.MEDIUM]
    )
    assert any("api, audit, authenticator" in f.message for f in ev.findings)
    [res] = ev.data["resources"]
    assert res["type"] == "AWS::EKS::Cluster" and res["compliant"] is False
    assert res["attributes"]["public_access_cidrs"] == ["0.0.0.0/0"]
    assert res["attributes"]["secrets_encrypted"] is False


def test_private_and_restricted_public_clusters_pass(make_ctx, session):
    logs = ["api", "audit", "authenticator"]
    _cluster(
        session,
        "private",
        vpc={"endpointPublicAccess": False, "endpointPrivateAccess": True},
        logs=logs,
    )
    _cluster(
        session,
        "allowlisted",
        vpc={"endpointPublicAccess": True, "publicAccessCidrs": ["203.0.113.0/24"]},
        logs=[*logs, "scheduler"],
    )
    ev = EksSecurity().execute(make_ctx())
    assert ev.status == Status.PASS and ev.findings == []
    by_id = {r["id"]: r for r in ev.data["resources"]}
    assert by_id["private"]["attributes"]["public_access_cidrs"] == []
    assert by_id["allowlisted"]["attributes"]["public_access_cidrs"] == ["203.0.113.0/24"]
    assert all(r["compliant"] for r in by_id.values())


def test_partial_logging_is_medium(make_ctx, session):
    _cluster(session, "half", vpc={"endpointPublicAccess": False}, logs=["api"])
    ev = EksSecurity().execute(make_ctx())
    assert [(f.severity, f.message) for f in ev.findings] == [
        (Severity.MEDIUM, "Control-plane logging is missing: audit, authenticator")
    ]


def test_cluster_cap_marks_incomplete(make_ctx, session):
    for i in range(3):
        _cluster(
            session,
            f"c{i}",
            vpc={"endpointPublicAccess": False},
            logs=["api", "audit", "authenticator"],
        )
    ev = EksSecurity().execute(make_ctx(max_items_per_check=2))
    assert ev.status == Status.ERROR and ev.data["truncated"] is True
    assert len(ev.data["resources"]) == 2
