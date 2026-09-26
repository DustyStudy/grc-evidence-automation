"""FIPS endpoint behavior. conftest.py turns FIPS off for moto-backed tests (moto only serves
the standard hostnames), so these tests use the real ``aws_session`` and fake clients."""

from __future__ import annotations

import socket
from types import SimpleNamespace

import pytest
from botocore.exceptions import ClientError

from grcevidence.collectors.aws.storage import S3Security
from grcevidence.models import Status
from grcevidence.runner import AccountConfig, Config, ConfigError, _assume
from grcevidence.runner import aws_session as real_aws_session  # bound before conftest patches


# ------------------------------------------------------------------------ config
def test_fips_is_on_by_default_and_strictly_boolean():
    assert Config().use_fips_endpoint is True
    assert Config.from_dict({}).use_fips_endpoint is True
    assert Config.from_dict({"use_fips_endpoint": False}).use_fips_endpoint is False
    with pytest.raises(ConfigError, match="use_fips_endpoint"):
        Config.from_dict({"use_fips_endpoint": "true"})


# ------------------------------------------------------------------------ sessions
@pytest.mark.parametrize(
    "region,service,expected",
    [
        ("us-east-1", "ec2", "ec2-fips.us-east-1.amazonaws.com"),
        ("us-east-1", "sts", "sts-fips.us-east-1.amazonaws.com"),
        ("us-west-2", "secretsmanager", "secretsmanager-fips.us-west-2.amazonaws.com"),
        ("us-east-1", "cloudcontrol", "cloudcontrolapi-fips.us-east-1.amazonaws.com"),
    ],
)
def test_aws_session_sends_every_client_to_fips(region, service, expected):
    sess = real_aws_session(True, region_name=region)
    assert sess.client(service).meta.endpoint_url == f"https://{expected}"


def test_aws_session_can_opt_out():
    sess = real_aws_session(False, region_name="us-east-1")
    assert "fips" not in sess.client("ec2").meta.endpoint_url


def test_assumed_role_sessions_keep_fips(monkeypatch):
    from grcevidence import runner

    monkeypatch.setattr(runner, "aws_session", real_aws_session)  # undo conftest's moto override
    creds = {"AccessKeyId": "AKIA", "SecretAccessKey": "s", "SessionToken": "t"}
    base = SimpleNamespace(
        client=lambda svc: SimpleNamespace(assume_role=lambda **kw: {"Credentials": creds})
    )
    acct = AccountConfig(role_arn="arn:aws:iam::111122223333:role/reader")
    sess = _assume(base, acct, True)
    assert "sts-fips.us-east-1" in sess.client("sts", region_name="us-east-1").meta.endpoint_url


# ------------------------------------------------------------------------ S3 bucket listing
class _Paginator:
    def __init__(self, pages):
        self._pages = pages

    def paginate(self, **kwargs):
        assert kwargs == {"TypeName": "AWS::S3::Bucket"}
        return iter(self._pages)


def _cloudcontrol(region, names=None, error=None):
    def get_paginator(op):
        assert op == "list_resources"
        if error:
            raise ClientError({"Error": {"Code": error}}, "ListResources")
        return _Paginator([{"ResourceDescriptions": [{"Identifier": n} for n in names or []]}])

    return SimpleNamespace(
        meta=SimpleNamespace(endpoint_url=f"https://cloudcontrolapi-fips.{region}.amazonaws.com"),
        get_paginator=get_paginator,
    )


class _NoListBuckets:
    def list_buckets(self):
        raise AssertionError("ListBuckets has no FIPS endpoint in the commercial partition")


def _fake_ctx(region, clients, use_fips=True):
    partition = "aws-us-gov" if region.startswith("us-gov-") else "aws"
    return SimpleNamespace(
        use_fips_endpoint=use_fips,
        partition=partition,
        region=region,
        client=lambda svc, region=None: clients(svc, region),
    )


def test_commercial_fips_lists_buckets_through_cloud_control_in_every_region(monkeypatch):
    regions = ["eu-west-1", "us-east-1", "us-west-2"]
    per_region = {"us-east-1": ["a", "b"], "us-west-2": ["b", "c"]}  # union, not per-region only

    def clients(svc, region):
        if svc == "ec2":
            return SimpleNamespace(
                describe_regions=lambda: {"Regions": [{"RegionName": r} for r in regions]}
            )
        assert svc == "cloudcontrol"
        return _cloudcontrol(region, per_region.get(region, []))

    def fake_getaddrinfo(host, port, *a, **k):
        if "eu-west-1" in host:
            raise socket.gaierror("no such host")
        return [("ok",)]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    names, method, skipped = S3Security._bucket_names(
        _fake_ctx("us-east-1", clients), _NoListBuckets()
    )
    assert names == ["a", "b", "c"] and method == "cloudcontrol"
    assert [r for r, _ in skipped] == ["eu-west-1"]


def test_cloud_control_errors_are_reported_not_hidden(monkeypatch):
    def clients(svc, region):
        if svc == "ec2":
            return SimpleNamespace(
                describe_regions=lambda: {"Regions": [{"RegionName": "us-east-1"}]}
            )
        return _cloudcontrol(region, error="AccessDeniedException")

    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [("ok",)])
    names, _, skipped = S3Security._bucket_names(_fake_ctx("us-east-1", clients), _NoListBuckets())
    assert names == [] and skipped == [
        ("us-east-1", "Cloud Control API returned AccessDeniedException")
    ]


def test_govcloud_and_fips_off_use_list_buckets():
    s3 = SimpleNamespace(list_buckets=lambda: {"Buckets": [{"Name": "x"}]})
    no_clients = lambda svc, region: pytest.fail("no other client should be used")  # noqa: E731
    for ctx in (
        _fake_ctx("us-gov-west-1", no_clients),  # s3-fips.us-gov-* resolves, so ListBuckets works
        _fake_ctx("us-east-1", no_clients, use_fips=False),
    ):
        assert S3Security._bucket_names(ctx, s3) == (["x"], "list_buckets", [])


def test_collector_end_to_end_with_cloud_control_listing(make_ctx, session, monkeypatch):
    s3 = session.client("s3")
    for name in ("alpha", "beta"):
        s3.create_bucket(Bucket=name)
    ctx = make_ctx()
    ctx.use_fips_endpoint = True
    real_client = ctx.client

    def client(svc, region=None):
        if svc == "ec2":
            return SimpleNamespace(
                describe_regions=lambda: {
                    "Regions": [{"RegionName": "us-east-1"}, {"RegionName": "ap-south-2"}]
                }
            )
        if svc == "cloudcontrol":
            return _cloudcontrol(
                region or "us-east-1", ["alpha", "beta"] if region == "us-east-1" else []
            )
        return real_client(svc, region)  # per-bucket S3 calls go to moto

    monkeypatch.setattr(ctx, "client", client)
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda host, *a, **k: (
            (_ for _ in ()).throw(socket.gaierror()) if "ap-south-2" in host else [("ok",)]
        ),
    )
    ev = S3Security().execute(ctx)
    assert ev.data["bucket_enumeration"] == "cloudcontrol"
    assert ev.data["buckets_examined"] == 2
    assert ev.data["regions_not_enumerated"] == ["ap-south-2"]
    assert ev.status == Status.FAIL  # the unreachable region is a finding, not silence
    assert any("ap-south-2" in f.message for f in ev.findings)
