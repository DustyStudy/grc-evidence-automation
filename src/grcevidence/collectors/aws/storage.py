"""Data-protection evidence: S3 exposure/encryption, KMS rotation, encryption at rest, backups."""

from __future__ import annotations

import socket
from typing import Any
from urllib.parse import urlsplit

from botocore.exceptions import BotoCoreError, ClientError

from grcevidence.collectors.base import Collector, Context, Result, paginate, register, resource
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
        if out_of_scope:
            # Cloud Control ListResources is region-scoped, so buckets there were never seen.
            findings.append(
                Finding(
                    "regions_out_of_scope",
                    "Buckets in enabled non-US region(s) were not examined (no FIPS listing "
                    f"there): {', '.join(out_of_scope)}",
                    Severity.MEDIUM,
                )
            )
        unversioned = unreadable = 0
        resources: list[dict[str, Any]] = []
        for name in buckets:
            bucket_findings, attrs = self._check_bucket(s3, name)
            versioning: bool | None = None
            try:
                versioning = s3.get_bucket_versioning(Bucket=name).get("Status") == "Enabled"
                if not versioning:
                    unversioned += 1
            except ClientError as exc:
                unreadable += 1
                bucket_findings.append(
                    Finding(
                        name,
                        f"Could not read versioning: {exc.response['Error']['Code']}",
                        Severity.LOW,
                    )
                )
            findings += bucket_findings
            resources.append(
                resource(
                    name, "AWS::S3::Bucket", not bucket_findings, **attrs, versioning=versioning
                )
            )
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
                "resources": resources,
            },
            # Nothing but unreadable versioning: the check could not be made, which is ERROR.
            status=Status.ERROR if unreadable and unreadable == len(findings) else None,
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
        endpoints) in every enabled US region. That listing is region-scoped, so enabled
        non-US regions are not queried and the caller reports them as unexamined. A US
        region that can't be reached over FIPS is reported, not silently skipped.
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
    def _check_bucket(s3: Any, name: str) -> tuple[list[Finding], dict[str, bool | None]]:
        """Findings for one bucket and the judged settings (None where a setting was unreadable)."""
        out: list[Finding] = []
        attrs: dict[str, bool | None] = dict.fromkeys(
            ("public_access_block_complete", "default_encryption", "policy_public")
        )
        try:
            cfg = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            attrs["public_access_block_complete"] = all(
                cfg.get(k)
                for k in (
                    "BlockPublicAcls",
                    "IgnorePublicAcls",
                    "BlockPublicPolicy",
                    "RestrictPublicBuckets",
                )
            )
            if not attrs["public_access_block_complete"]:
                out.append(
                    Finding(name, "Public access block is only partially enabled", Severity.HIGH)
                )
        except ClientError as exc:
            if exc.response["Error"]["Code"] in _MISSING:
                attrs["public_access_block_complete"] = False
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
            attrs["default_encryption"] = bool(rules)
            if not rules:
                out.append(Finding(name, "No default encryption rule", Severity.MEDIUM))
        except ClientError as exc:
            if exc.response["Error"]["Code"] in _MISSING:
                attrs["default_encryption"] = False
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
            status = s3.get_bucket_policy_status(Bucket=name).get("PolicyStatus", {})
            attrs["policy_public"] = bool(status.get("IsPublic"))
            if attrs["policy_public"]:
                out.append(
                    Finding(name, "Bucket policy makes the bucket public", Severity.CRITICAL)
                )
        except ClientError as exc:
            if exc.response["Error"]["Code"] in _MISSING:
                attrs["policy_public"] = False  # no bucket policy at all
            else:
                out.append(
                    Finding(
                        name,
                        f"Could not read policy status: {exc.response['Error']['Code']}",
                        Severity.LOW,
                    )
                )
        return out, attrs


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
        resources: list[dict[str, Any]] = []
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
            enabled = bool(kms.get_key_rotation_status(KeyId=key_id)["KeyRotationEnabled"])
            resources.append(
                resource(meta["Arn"], "AWS::KMS::Key", enabled, rotation_enabled=enabled)
            )
            if enabled:
                rotating += 1
            else:
                findings.append(
                    Finding(meta["Arn"], "Automatic key rotation is disabled", Severity.MEDIUM)
                )
        return Result(
            summary=f"{rotating}/{examined} rotatable customer-managed key(s) have rotation enabled",
            findings=findings,
            data={"keys_examined": examined, "keys_rotating": rotating, "resources": resources},
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
        cap = ctx.params.max_items_per_check
        instances = paginate(
            ctx.client("rds"),
            "describe_db_instances",
            "DBInstances",
            max(cap - 1, 0),  # the region's EBS setting takes one slot of the population
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
                "resources": [
                    resource(
                        f"ec2:{ctx.region}",
                        "AWS::EC2::EBSEncryptionByDefault",
                        bool(ebs_default),
                        encryption_by_default=bool(ebs_default),
                    ),
                    *(
                        resource(
                            i["DBInstanceIdentifier"],
                            "AWS::RDS::DBInstance",
                            bool(i.get("StorageEncrypted")),
                            storage_encrypted=bool(i.get("StorageEncrypted")),
                        )
                        for i in instances
                    ),
                ],
            },
            truncated_at=cap if instances.truncated else None,
        )


@register
class Backups(Collector):
    id = "aws.backups"
    title = "Backup retention (RDS) and AWS Backup plans"
    permissions = ("rds:DescribeDBInstances", "backup:ListBackupPlans")

    def collect(self, ctx: Context) -> Result:
        cap = ctx.params.max_items_per_check
        instances = paginate(ctx.client("rds"), "describe_db_instances", "DBInstances", cap)
        # Plans share the capped population with the instances.
        plans = paginate(
            ctx.client("backup"), "list_backup_plans", "BackupPlansList", cap - len(instances)
        )
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
            "resources": [
                *(
                    resource(
                        i["DBInstanceIdentifier"],
                        "AWS::RDS::DBInstance",
                        int(i.get("BackupRetentionPeriod", 0)) >= minimum,
                        backup_retention_days=int(i.get("BackupRetentionPeriod", 0)),
                    )
                    for i in instances
                ),
                *(resource(p["BackupPlanArn"], "AWS::Backup::BackupPlan", True) for p in plans),
            ],
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
            truncated_at=cap if instances.truncated or plans.truncated else None,
        )
