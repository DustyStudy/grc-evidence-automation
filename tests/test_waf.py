"""WAF coverage collectors.

moto: elbv2, wafv2 (associate_web_acl / get_web_acl_for_resource) and cloudfront.
Stubbed: API Gateway, via botocore's Stubber (responses validated against the service model),
because moto's apigateway backend needs the moto[apigateway] extra (openapi-spec-validator),
which the dev dependencies don't install. The FIPS paths use fake clients: conftest.py runs moto
with FIPS off, and moto only serves the standard hostnames.
"""

from __future__ import annotations

import socket
from types import SimpleNamespace

import boto3
import pytest
from botocore.stub import Stubber

from grcevidence.collectors.aws import waf
from grcevidence.collectors.aws.waf import WafCloudFront, WafCoverage
from grcevidence.models import Severity, Status


def _subnets(session):
    ec2 = session.client("ec2")
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    return [
        ec2.create_subnet(VpcId=vpc, CidrBlock=f"10.0.{i}.0/24", AvailabilityZone=az)["Subnet"][
            "SubnetId"
        ]
        for i, az in enumerate(("us-east-1a", "us-east-1b"))
    ]


def _web_acl(session, scope="REGIONAL"):
    return session.client("wafv2").create_web_acl(
        Name=f"acl-{scope.lower()}",
        Scope=scope,
        DefaultAction={"Allow": {}},
        VisibilityConfig={
            "SampledRequestsEnabled": False,
            "CloudWatchMetricsEnabled": False,
            "MetricName": "acl",
        },
    )["Summary"]["ARN"]


def _stub_apigateway(ctx, apis):
    """Serve ``apis`` ({id: (endpoint types, prod stage's webAclArn or None)}) from a stubbed
    API Gateway client; every other service still goes to moto."""
    client = boto3.client("apigateway", region_name=ctx.region)
    stubber = Stubber(client)
    stubber.add_response(
        "get_rest_apis",
        {"items": [{"id": i, "endpointConfiguration": {"types": t}} for i, (t, _) in apis.items()]},
    )
    for api_id, (types, acl) in apis.items():
        if "PRIVATE" not in types:  # the collector must not even read private APIs' stages
            stage = {"stageName": "prod", **({"webAclArn": acl} if acl else {})}
            stubber.add_response("get_stages", {"item": [stage]}, {"restApiId": api_id})
    stubber.activate()
    real = ctx.session.client
    ctx.session = SimpleNamespace(
        client=lambda svc, **kw: client if svc == "apigateway" else real(svc, **kw)
    )
    return stubber


def _distribution(session, ref, web_acl="", enabled=True):
    return session.client("cloudfront").create_distribution(
        DistributionConfig={
            "CallerReference": ref,
            "Comment": "",
            "Enabled": enabled,
            "WebACLId": web_acl,
            "Origins": {
                "Quantity": 1,
                "Items": [
                    {
                        "Id": "o",
                        "DomainName": "example.s3.amazonaws.com",
                        "S3OriginConfig": {"OriginAccessIdentity": ""},
                    }
                ],
            },
            "DefaultCacheBehavior": {
                "TargetOriginId": "o",
                "ViewerProtocolPolicy": "redirect-to-https",
                "MinTTL": 0,
            },
        }
    )["Distribution"]["Id"]


# ------------------------------------------------------------------ regional: ALB + REST APIs
def test_waf_coverage_flags_unprotected_public_entry_points(make_ctx, session):
    elbv2, subnets = session.client("elbv2"), _subnets(session)
    protected = elbv2.create_load_balancer(Name="protected", Subnets=subnets)["LoadBalancers"][0]
    bare = elbv2.create_load_balancer(Name="bare", Subnets=subnets)["LoadBalancers"][0]
    elbv2.create_load_balancer(Name="internal", Subnets=subnets, Scheme="internal")
    elbv2.create_load_balancer(Name="nlb", Subnets=subnets, Type="network")
    acl = _web_acl(session)
    session.client("wafv2").associate_web_acl(
        WebACLArn=acl, ResourceArn=protected["LoadBalancerArn"]
    )
    guarded, open_api = "guarded1", "open1"
    ctx = make_ctx()
    stubber = _stub_apigateway(
        ctx,
        {
            guarded: (["REGIONAL"], acl),
            open_api: (["EDGE"], None),
            "private1": (["PRIVATE"], None),  # not internet-facing: skipped
        },
    )

    ev = WafCoverage().execute(ctx)
    stubber.assert_no_pending_responses()
    assert ev.status == Status.FAIL and ev.region == "us-east-1"
    by_id = {r["id"]: r for r in ev.data["resources"]}
    assert set(by_id) == {
        protected["LoadBalancerArn"],
        bare["LoadBalancerArn"],
        f"{guarded}/prod",
        f"{open_api}/prod",
    }
    assert by_id[protected["LoadBalancerArn"]]["compliant"] is True
    assert by_id[protected["LoadBalancerArn"]]["attributes"] == {
        "web_acl_arn": acl,
        "scheme": "internet-facing",
    }
    assert by_id[f"{guarded}/prod"]["attributes"] == {
        "web_acl_arn": acl,
        "endpoint_types": ["REGIONAL"],
    }
    assert by_id[f"{open_api}/prod"]["type"] == "AWS::ApiGateway::Stage"
    assert {f.resource for f in ev.findings} == {bare["LoadBalancerArn"], f"{open_api}/prod"}
    assert {f.severity for f in ev.findings} == {Severity.MEDIUM}
    assert "2/4" in ev.summary


def test_waf_coverage_not_applicable_without_public_entry_points(make_ctx, session):
    session.client("elbv2").create_load_balancer(
        Name="internal", Subnets=_subnets(session), Scheme="internal"
    )
    ctx = make_ctx()
    _stub_apigateway(ctx, {"private1": (["PRIVATE"], None)})
    ev = WafCoverage().execute(ctx)
    assert ev.status == Status.NOT_APPLICABLE and ev.data["resources"] == []


def test_waf_coverage_cap_marks_scan_incomplete(make_ctx, session):
    elbv2, subnets = session.client("elbv2"), _subnets(session)
    for name in ("a", "b"):
        elbv2.create_load_balancer(Name=name, Subnets=subnets)
    ctx = make_ctx(max_items_per_check=1)
    _stub_apigateway(ctx, {})
    ev = WafCoverage().execute(ctx)
    assert ev.status == Status.FAIL and ev.data["truncated"] is True
    assert len(ev.data["resources"]) == 1
    assert any("Incomplete" in f.message for f in ev.findings)


# ------------------------------------------------------------------ global: CloudFront
def test_waf_cloudfront_flags_distribution_without_web_acl(make_ctx, session):
    acl = _web_acl(session, scope="CLOUDFRONT")
    guarded = _distribution(session, "guarded", web_acl=acl)
    bare = _distribution(session, "bare")
    _distribution(session, "off", enabled=False)  # serves no traffic: skipped

    ev = WafCloudFront().execute(make_ctx())
    assert ev.status == Status.FAIL and ev.region == "global"
    by_id = {r["id"]: r for r in ev.data["resources"]}
    assert set(by_id) == {guarded, bare}
    assert by_id[guarded]["compliant"] and by_id[guarded]["attributes"] == {"web_acl_arn": acl}
    assert by_id[bare]["attributes"] == {"web_acl_arn": None}
    assert [(f.resource, f.severity) for f in ev.findings] == [(bare, Severity.MEDIUM)]


def test_waf_cloudfront_not_applicable_without_distributions(make_ctx):
    ev = WafCloudFront().execute(make_ctx())
    assert ev.status == Status.NOT_APPLICABLE and ev.data["resources"] == []


def test_waf_cloudfront_cap_marks_scan_incomplete(make_ctx, session):
    for ref in ("a", "b"):
        _distribution(session, ref)
    ev = WafCloudFront().execute(make_ctx(max_items_per_check=1))
    assert ev.status == Status.FAIL and ev.data["truncated"] is True
    assert len(ev.data["resources"]) == 1


def test_waf_cloudfront_not_applicable_in_govcloud(make_ctx):
    ev = WafCloudFront().execute(make_ctx(region="us-gov-west-1"))
    assert ev.status == Status.NOT_APPLICABLE and "GovCloud" in ev.summary


# ------------------------------------------------------------------ FIPS (fake clients)
def _client(host, pages=None):
    return SimpleNamespace(
        meta=SimpleNamespace(endpoint_url=f"https://{host}"),
        get_paginator=lambda op: SimpleNamespace(
            paginate=lambda: SimpleNamespace(search=lambda expr: iter(pages or []))
        ),
    )


def _fips_ctx(make_ctx, region, clients):
    ctx = make_ctx(region=region)
    ctx.use_fips_endpoint = True
    calls = []

    def client(service, region_name=None, endpoint_url=None, config=None):
        calls.append((service, region_name, endpoint_url))
        return clients[service]

    ctx.session = SimpleNamespace(client=client)
    return ctx, calls


def _dns(monkeypatch, resolvable):
    def getaddrinfo(host, port):
        if host not in resolvable:
            raise socket.gaierror(11002, "getaddrinfo failed")
        return []

    monkeypatch.setattr(waf.socket, "getaddrinfo", getaddrinfo)


def test_waf_cloudfront_fips_uses_documented_fips_endpoint(make_ctx, monkeypatch):
    host = "cloudfront-fips.amazonaws.com"
    _dns(monkeypatch, {host})
    pages = [None, {"Id": "E1", "WebACLId": "arn:aws:wafv2:us-east-1:1:global/webacl/a/1"}]
    ctx, calls = _fips_ctx(make_ctx, "us-west-2", {"cloudfront": _client(host, pages)})
    ev = WafCloudFront().execute(ctx)
    assert calls == [("cloudfront", "us-east-1", f"https://{host}")]
    assert ev.status == Status.PASS and ev.data["resources"][0]["id"] == "E1"


def test_waf_cloudfront_fips_unresolvable_is_error(make_ctx, monkeypatch):
    _dns(monkeypatch, set())
    ctx, _ = _fips_ctx(make_ctx, "cn-north-1", {"cloudfront": _client("cloudfront-fips.cn")})
    ev = WafCloudFront().execute(ctx)
    assert ev.status == Status.ERROR and "cloudfront-fips.cn" in ev.summary


@pytest.mark.parametrize("missing", ["elasticloadbalancing-fips", "wafv2-fips", "apigateway-fips"])
def test_waf_coverage_fips_unresolvable_is_error(make_ctx, monkeypatch, missing):
    hosts = {
        svc: f"{name}.eu-west-1.amazonaws.com"
        for svc, name in (
            ("elbv2", "elasticloadbalancing-fips"),
            ("wafv2", "wafv2-fips"),
            ("apigateway", "apigateway-fips"),
        )
    }
    _dns(monkeypatch, {h for h in hosts.values() if not h.startswith(missing)})
    ctx, _ = _fips_ctx(make_ctx, "eu-west-1", {s: _client(h) for s, h in hosts.items()})
    ev = WafCoverage().execute(ctx)
    assert ev.status == Status.ERROR and missing in ev.summary
