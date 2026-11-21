"""Web application firewall evidence: AWS WAF web ACLs on internet-facing web entry points.

AWS WAF attaches to Application Load Balancers, API Gateway REST API stages and CloudFront
distributions. HTTP and WebSocket APIs (API Gateway v2) cannot take a web ACL, so they are not
examined; the way to filter them is a CloudFront distribution in front, which
``aws.waf_cloudfront`` covers. Web ACLs from WAF Classic (end of support September 2025) are
not seen on load balancers.
"""

from __future__ import annotations

import socket
from itertools import islice
from typing import Any
from urllib.parse import urlsplit

from grcevidence.collectors.base import (
    _BOTO_CONFIG,
    Collector,
    Context,
    Result,
    paginate,
    register,
    resource,
)
from grcevidence.models import Finding, Severity, Status

# With FIPS on, botocore resolves CloudFront to cloudfront-fips.aws-global.amazonaws.com, which
# has no address records; this is the FIPS endpoint AWS documents for CloudFront.
_CLOUDFRONT_FIPS = "https://cloudfront-fips.amazonaws.com"

_NO_ACL = {
    "AWS::ElasticLoadBalancingV2::LoadBalancer": "Internet-facing Application Load Balancer",
    "AWS::ApiGateway::Stage": "Public REST API stage",
    "AWS::CloudFront::Distribution": "CloudFront distribution",
}


def _unreachable_fips(ctx: Context, *clients: Any) -> Result | None:
    """An ERROR result when FIPS is on and a client's endpoint has no address records, so a
    missing FIPS endpoint is reported rather than retried into a generic connection error."""
    if not ctx.use_fips_endpoint:
        return None
    for client in clients:
        host = urlsplit(client.meta.endpoint_url).hostname or ""
        try:
            socket.getaddrinfo(host, 443)
        except OSError:
            return Result(
                summary=f"Could not collect: no FIPS endpoint at {host}",
                findings=[
                    Finding(host, "FIPS endpoint does not resolve; not checked", Severity.LOW)
                ],
                status=Status.ERROR,
            )
    return None


def _result(resources: list[dict[str, Any]], what: str, truncated_at: int | None) -> Result:
    findings = [
        Finding(r["id"], f"{_NO_ACL[r['type']]} has no AWS WAF web ACL", Severity.MEDIUM)
        for r in resources
        if not r["compliant"]
    ]
    return Result(
        summary=f"{len(resources) - len(findings)}/{len(resources)} {what} have a WAF web ACL",
        findings=findings,
        data={"resources": resources},
        status=None if resources else Status.NOT_APPLICABLE,
        truncated_at=truncated_at,
    )


@register
class WafCoverage(Collector):
    id = "aws.waf_coverage"
    title = "AWS WAF on internet-facing load balancers and REST API stages"
    permissions = (
        "elasticloadbalancing:DescribeLoadBalancers",
        "wafv2:GetWebACLForResource",
        "apigateway:GET",
    )

    def collect(self, ctx: Context) -> Result:
        elbv2, wafv2, apigw = ctx.client("elbv2"), ctx.client("wafv2"), ctx.client("apigateway")
        if error := _unreachable_fips(ctx, elbv2, wafv2, apigw):
            return error
        limit = ctx.params.max_items_per_check
        lbs = paginate(elbv2, "describe_load_balancers", "LoadBalancers", limit)
        apis = paginate(apigw, "get_rest_apis", "items", limit)
        resources = []
        for lb in lbs:
            scheme = lb.get("Scheme", "internet-facing")  # the API's default when unset
            if lb.get("Type") != "application" or scheme != "internet-facing":
                continue
            arn = lb["LoadBalancerArn"]
            acl = wafv2.get_web_acl_for_resource(ResourceArn=arn).get("WebACL") or {}
            resources.append(
                resource(
                    arn,
                    "AWS::ElasticLoadBalancingV2::LoadBalancer",
                    bool(acl),
                    web_acl_arn=acl.get("ARN"),
                    scheme=scheme,
                )
            )
        for api in apis:
            types = api.get("endpointConfiguration", {}).get("types", [])
            if "PRIVATE" in types:
                continue  # reachable only through a VPC endpoint
            for stage in apigw.get_stages(restApiId=api["id"]).get("item", []):
                acl_arn = stage.get("webAclArn") or None
                resources.append(
                    resource(
                        f"{api['id']}/{stage['stageName']}",
                        "AWS::ApiGateway::Stage",
                        acl_arn is not None,
                        web_acl_arn=acl_arn,
                        endpoint_types=types,
                    )
                )
        return _result(
            resources,
            "internet-facing ALB(s) and public REST API stage(s)",
            limit if lbs.truncated or apis.truncated else None,
        )


@register
class WafCloudFront(Collector):
    id = "aws.waf_cloudfront"
    title = "AWS WAF on CloudFront distributions"
    scope = "global"  # CloudFront's control plane is global (us-east-1)
    permissions = ("cloudfront:ListDistributions",)

    def collect(self, ctx: Context) -> Result:
        if ctx.partition == "aws-us-gov":
            return Result(
                "CloudFront is not available in AWS GovCloud (US)", status=Status.NOT_APPLICABLE
            )
        if ctx.use_fips_endpoint and ctx.partition == "aws":
            cf = ctx.session.client(
                "cloudfront",
                region_name="us-east-1",
                endpoint_url=_CLOUDFRONT_FIPS,
                config=_BOTO_CONFIG,
            )
        else:
            cf = ctx.client("cloudfront")
        if error := _unreachable_fips(ctx, cf):
            return error
        limit = ctx.params.max_items_per_check
        # The items are nested (DistributionList.Items), which paginate() doesn't read; a page
        # without items yields None.
        items = cf.get_paginator("list_distributions").paginate().search("DistributionList.Items[]")
        listed = list(islice((d for d in items if d), limit + 1))
        resources = [
            resource(
                d["Id"],
                "AWS::CloudFront::Distribution",
                bool(d.get("WebACLId")),
                web_acl_arn=d.get("WebACLId") or None,
            )
            for d in listed[:limit]
            if d.get("Enabled", True)  # a disabled distribution serves no traffic
        ]
        return _result(
            resources,
            "enabled CloudFront distribution(s)",
            limit if len(listed) > limit else None,
        )
