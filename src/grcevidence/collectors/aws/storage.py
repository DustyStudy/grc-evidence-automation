"""Data-protection evidence: S3 exposure/encryption, KMS rotation, encryption at rest, backups."""

from __future__ import annotations

import socket
from typing import Any
from urllib.parse import urlsplit

from botocore.exceptions import BotoCoreError, ClientError

from grcevidence.collectors.base import Collector, Context, Result, paginate, register
from grcevidence.models import Finding, Severity, Status

_MISSING = {
    "NoSuchPublicAccessBlockConfiguration",
    "ServerSideEncryptionConfigurationNotFoundError",
    "NoSuchBucketPolicy",
}


@register
class S3Security(Collector):
    id = "aws.s3_security"
    title = "S3 public access, default encryption and versioning"
    scope = "global"
    permissions = (
        "cloudformation:ListResources",
        "ec2:DescribeRegions",
        "s3:ListAllMyBuckets",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetEncryptionConfiguration",
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketVersioning",
    )

    def collect(self, ctx: Context) -> Result:
        s3 = ctx.client("s3")
        buckets, method, not_enumerated, out_of_scope = self._bucket_names(ctx, s3)
        limit = ctx.params.max_items_per_check
        truncated = len(buckets) > limit
        buckets = buckets[:limit]

        findings: list[Finding] = [
            Finding(
                region,
                f"Buckets in {region} were not enumerated: {reason}",
                Severity.MEDIUM,
            )
            for region, reason in not_enumerated
        ]
        unversioned = 0
        for name in buckets:
            findings += self._check_bucket(s3, name)
            try:
                if s3.get_bucket_versioning(Bucket=name).get("Status") != "Enabled":
                    unversioned += 1
            except ClientError:
                pass
        return Result(
            summary=f"{len(buckets)} bucket(s) examined; {len(findings)} finding(s)",
            findings=findings,
            data={
                "buckets_examined": len(buckets),
                "buckets_without_versioning": unversioned,
                "bucket_enumeration": method,
                "regions_not_enumerated": [r for r, _ in not_enumerated],
                "regions_out_of_scope": out_of_scope,
                "truncated": truncated,
            },
            truncated_at=limit if truncated else None,
        )

    @staticmethod
    def _bucket_names(
        ctx: Context, s3: Any
    ) -> tuple[list[str], str, list[tuple[str, str]], list[str]]:
        """Bucket names, how they were listed, US regions that couldn't be enumerated (with
        the reason), and enabled non-US regions left out of scope.

        In the commercial partition S3 has no FIPS endpoint for ListBuckets: the bare
        s3-fips.<region> hostname has no address records, only bucket-scoped hosts do. With
        FIPS on there, buckets are listed through Cloud Control API (which has FIPS
        endpoints) in every enabled US region; FedRAMP boundaries are US-only, so non-US
        regions are recorded as out of scope rather than raised as findings. A US region
        that can't be reached over FIPS is reported, not silently skipped.
        """
        if not (ctx.use_fips_endpoint and ctx.partition == "aws"):
            listed = [b["Name"] for b in s3.list_buckets().get("Buckets", [])]
            return listed, "list_buckets", [], []
        enabled = sorted(r["RegionName"] for r in ctx.client("ec2").describe_regions()["Regions"])
        regions = [r for r in enabled if r.startswith("us-")]
        out_of_scope = [r for r in enabled if not r.startswith("us-")]
        names: set[str] = set()
        skipped: list[tuple[str, str]] = []
        for region in regions:
            try:
                cc = ctx.client("cloudcontrol", region=region)
                host = urlsplit(cc.meta.endpoint_url).hostname or ""
                socket.getaddrinfo(host, 443)
            except (BotoCoreError, OSError):
                skipped.append((region, "no FIPS endpoint for Cloud Control API in this region"))
                continue
            try:
                for page in cc.get_paginator("list_resources").paginate(TypeName="AWS::S3::Bucket"):
                    names.update(d["Identifier"] for d in page.get("ResourceDescriptions", []))
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "ClientError")
                skipped.append((region, f"Cloud Control API returned {code}"))
        return sorted(names), "cloudcontrol", skipped, out_of_scope

    @staticmethod
    def _check_bucket(s3: Any, name: str) -> list[Finding]:
        out: list[Finding] = []
        try:
            cfg = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            if not all(
                cfg.get(k)
                for k in (
                    "BlockPublicAcls",
                    "IgnorePublicAcls",
                    "BlockPublicPolicy",
                    "RestrictPublicBuckets",
                )
            ):
                out.append(
                    Finding(name, "Public access block is only partially enabled", Severity.HIGH)
                )
        except ClientError as exc:
            if exc.response["Error"]["Code"] in _MISSING:
                out.append(Finding(name, "No public access block configured", Severity.HIGH))
            else:
                out.append(
                    Finding(
                        name,
                        f"Could not read public access block: {exc.response['Error']['Code']}",
                        Severity.LOW,
                    )
                )
        try:
            rules = s3.get_bucket_encryption(Bucket=name)["ServerSideEncryptionConfiguration"][
                "Rules"
            ]
            if not rules:
                out.append(Finding(name, "No default encryption rule", Severity.MEDIUM))
        except ClientError as exc:
            if exc.response["Error"]["Code"] in _MISSING:
                out.append(Finding(name, "No default encryption configured", Severity.MEDIUM))
            else:
                out.append(
                    Finding(
                        name,
                        f"Could not read encryption: {exc.response['Error']['Code']}",
                        Severity.LOW,
                    )
                )
        try:
            if s3.get_bucket_policy_status(Bucket=name).get("PolicyStatus", {}).get("IsPublic"):
                out.append(
                    Finding(name, "Bucket policy makes the bucket public", Severity.CRITICAL)
                )
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in _MISSING:
                out.append(
                    Finding(
                        name,
                        f"Could not read policy status: {exc.response['Error']['Code']}",
                        Severity.LOW,
                    )
                )
        return out


@register
class KmsRotation(Collector):
    id = "aws.kms_rotation"
    title = "Customer-managed KMS key rotation"
    permissions = ("kms:ListKeys", "kms:DescribeKey", "kms:GetKeyRotationStatus")

    def collect(self, ctx: Context) -> Result:
        kms = ctx.client("kms")
        keys = paginate(kms, "list_keys", "Keys", ctx.params.max_items_per_check)
        key_ids = [k["KeyId"] for k in keys]
        findings: list[Finding] = []
        examined = rotating = 0
        for key_id in key_ids:
            meta = kms.describe_key(KeyId=key_id)["KeyMetadata"]
            if (
                meta.get("KeyManager") != "CUSTOMER"
                or meta.get("KeyState") != "Enabled"
                or meta.get("KeySpec", "SYMMETRIC_DEFAULT") != "SYMMETRIC_DEFAULT"
                or meta.get("Origin") == "EXTERNAL"
            ):
                continue  # rotation applies only to enabled, symmetric, KMS-generated CMKs
            examined += 1
            if kms.get_key_rotation_status(KeyId=key_id)["KeyRotationEnabled"]:
                rotating += 1
            else:
                findings.append(
                    Finding(meta["Arn"], "Automatic key rotation is disabled", Severity.MEDIUM)
                )
        return Result(
            summary=f"{rotating}/{examined} rotatable customer-managed key(s) have rotation enabled",
            findings=findings,
            data={"keys_examined": examined, "keys_rotating": rotating},
            status=Status.NOT_APPLICABLE if examined == 0 else None,
            truncated_at=ctx.params.max_items_per_check if keys.truncated else None,
        )


@register
class EncryptionAtRest(Collector):
    id = "aws.encryption_at_rest"
    title = "EBS default encryption and RDS storage encryption"
    permissions = ("ec2:GetEbsEncryptionByDefault", "rds:DescribeDBInstances")

    def collect(self, ctx: Context) -> Result:
        ebs_default = ctx.client("ec2").get_ebs_encryption_by_default()["EbsEncryptionByDefault"]
        instances = paginate(
            ctx.client("rds"),
            "describe_db_instances",
            "DBInstances",
            ctx.params.max_items_per_check,
        )
        findings: list[Finding] = []
        if not ebs_default:
            findings.append(
                Finding(
                    f"ec2:{ctx.region}",
                    "EBS encryption by default is disabled in this region",
                    Severity.MEDIUM,
                )
            )
        unencrypted = [i for i in instances if not i.get("StorageEncrypted")]
        findings += [
            Finding(
                i["DBInstanceIdentifier"], "RDS instance storage is not encrypted", Severity.HIGH
            )
            for i in unencrypted
        ]
        return Result(
            summary=(
                f"EBS default encryption {'on' if ebs_default else 'OFF'}; "
                f"{len(instances) - len(unencrypted)}/{len(instances)} RDS instance(s) encrypted"
            ),
            findings=findings,
            data={
                "ebs_encryption_by_default": ebs_default,
                "rds_instances": len(instances),
                "rds_unencrypted": len(unencrypted),
            },
            truncated_at=ctx.params.max_items_per_check if instances.truncated else None,
        )


@register
class Backups(Collector):
    id = "aws.backups"
    title = "Backup retention (RDS) and AWS Backup plans"
    permissions = ("rds:DescribeDBInstances", "backup:ListBackupPlans")

    def collect(self, ctx: Context) -> Result:
        instances = paginate(
            ctx.client("rds"),
            "describe_db_instances",
            "DBInstances",
            ctx.params.max_items_per_check,
        )
        plans = ctx.client("backup").list_backup_plans().get("BackupPlansList", [])
        minimum = ctx.params.min_backup_retention_days
        findings = [
            Finding(
                i["DBInstanceIdentifier"],
                f"Automated backup retention {i.get('BackupRetentionPeriod', 0)}d < required {minimum}d",
                Severity.MEDIUM,
            )
            for i in instances
            if int(i.get("BackupRetentionPeriod", 0)) < minimum
        ]
        data = {
            "rds_instances": len(instances),
            "backup_plans": len(plans),
            "min_retention_days": minimum,
        }
        if not instances and not plans:
            return Result(
                "No RDS instances or AWS Backup plans in this region",
                data=data,
                status=Status.NOT_APPLICABLE,
            )
        return Result(
            summary=f"{len(instances)} RDS instance(s), {len(plans)} AWS Backup plan(s); {len(findings)} finding(s)",
            findings=findings,
            data=data,
            truncated_at=ctx.params.max_items_per_check if instances.truncated else None,
        )
