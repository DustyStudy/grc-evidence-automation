from __future__ import annotations

import boto3
import pytest
from botocore.exceptions import ClientError

from grcevidence.collectors.aws.iam import (
    IamAccessKeys,
    IamMfa,
    IamPasswordPolicy,
    IamPrivilegedAccess,
)
from grcevidence.collectors.aws.monitoring import (
    CloudTrail,
    ConfigRecorder,
    NetworkExposure,
    ThreatDetection,
    VpcFlowLogs,
)
from grcevidence.collectors.aws.storage import (
    Backups,
    EncryptionAtRest,
    KmsRotation,
    S3Security,
)
from grcevidence.models import Severity, Status


def messages(ev):
    return [f.message for f in ev.findings]


# ------------------------------------------------------------------------- IAM
def test_mfa_flags_root_and_console_user_without_mfa(make_ctx, session):
    iam = session.client("iam")
    iam.create_user(UserName="alice")
    iam.create_login_profile(
        UserName="alice", Password="Aa1!aaaaaaaaaaaa", PasswordResetRequired=False
    )
    iam.create_user(UserName="svc-bot")  # no console access: must not be flagged

    ev = IamMfa().execute(make_ctx())
    assert ev.status == Status.FAIL and ev.region == "global"
    assert ev.data["console_users"] == 1 and ev.data["console_users_without_mfa"] == 1
    assert {f.resource for f in ev.findings} == {"root", "alice"}
    assert any(f.severity == Severity.CRITICAL for f in ev.findings)
    assert ev.verify() and ev.controls["soc2"] == ["CC6.1", "CC6.6"]


def test_mfa_user_with_device_passes_user_check(make_ctx, session):
    iam = session.client("iam")
    iam.create_user(UserName="bob")
    iam.create_login_profile(
        UserName="bob", Password="Aa1!aaaaaaaaaaaa", PasswordResetRequired=False
    )
    device = iam.create_virtual_mfa_device(VirtualMFADeviceName="bob-mfa")["VirtualMFADevice"]
    iam.enable_mfa_device(
        UserName="bob",
        SerialNumber=device["SerialNumber"],
        AuthenticationCode1="123456",
        AuthenticationCode2="654321",
    )
    ev = IamMfa().execute(make_ctx())
    assert ev.data["console_users_without_mfa"] == 0
    assert "bob" not in {f.resource for f in ev.findings}


def test_password_policy_missing_weak_and_strong(make_ctx, session):
    iam = session.client("iam")
    ev = IamPasswordPolicy().execute(make_ctx())
    assert ev.status == Status.FAIL and ev.data["policy_configured"] is False

    iam.update_account_password_policy(MinimumPasswordLength=8, PasswordReusePrevention=2)
    weak = IamPasswordPolicy().execute(make_ctx())
    assert weak.status == Status.FAIL
    assert any("Minimum length 8" in m for m in messages(weak))

    iam.update_account_password_policy(
        MinimumPasswordLength=14,
        PasswordReusePrevention=24,
        RequireUppercaseCharacters=True,
        RequireLowercaseCharacters=True,
        RequireNumbers=True,
        RequireSymbols=True,
        MaxPasswordAge=90,
    )
    strong = IamPasswordPolicy().execute(make_ctx())
    assert strong.status == Status.PASS and strong.data["minimum_length"] == 14


def test_password_policy_thresholds_are_configurable(make_ctx, session):
    session.client("iam").update_account_password_policy(
        MinimumPasswordLength=10,
        PasswordReusePrevention=5,
        RequireUppercaseCharacters=True,
        RequireLowercaseCharacters=True,
        RequireNumbers=True,
        RequireSymbols=True,
    )
    ev = IamPasswordPolicy().execute(make_ctx(password_min_length=10, password_reuse_prevention=5))
    assert ev.status == Status.PASS


def test_access_keys_old_and_unused(make_ctx, session, monkeypatch):
    iam = session.client("iam")
    iam.create_user(UserName="carol")
    iam.create_access_key(UserName="carol")
    # Key was created "now" in moto; evaluate as if 200 days later.
    from datetime import UTC, datetime

    later = datetime.now(UTC).replace(microsecond=0)
    ctx = make_ctx()
    ctx.now = later.replace(year=later.year + 1)
    ev = IamAccessKeys().execute(ctx)
    assert ev.status == Status.FAIL
    text = " ".join(messages(ev))
    assert "days old" in text and "never used" in text
    assert ev.data["active_access_keys"] == 1


def test_access_keys_fresh_key_passes(make_ctx, session):
    session.client("iam").create_user(UserName="dave")
    session.client("iam").create_access_key(UserName="dave")
    from datetime import UTC, datetime

    ctx = make_ctx()
    ctx.now = datetime.now(UTC)
    assert IamAccessKeys().execute(ctx).status == Status.PASS


def test_privileged_access_flags_direct_user_admin(make_ctx, session, monkeypatch):
    monkeypatch.setenv("MOTO_IAM_LOAD_MANAGED_POLICIES", "true")  # AdministratorAccess must exist
    iam = session.client("iam")
    arn = "arn:aws:iam::aws:policy/AdministratorAccess"
    iam.create_user(UserName="erin")
    iam.attach_user_policy(UserName="erin", PolicyArn=arn)
    iam.create_group(GroupName="admins")
    iam.attach_group_policy(GroupName="admins", PolicyArn=arn)
    ev = IamPrivilegedAccess().execute(make_ctx())
    assert ev.status == Status.FAIL
    assert ev.data["admin_users"] == ["erin"] and ev.data["admin_groups"] == ["admins"]


def test_privileged_access_clean_account_passes(make_ctx):
    assert IamPrivilegedAccess().execute(make_ctx()).status == Status.PASS


# -------------------------------------------------------------------------- S3
def test_s3_security_flags_missing_pab_and_encryption(make_ctx, session):
    s3 = session.client("s3")
    s3.create_bucket(Bucket="open-bucket")
    s3.create_bucket(Bucket="tight-bucket")
    s3.put_public_access_block(
        Bucket="tight-bucket",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    s3.put_bucket_encryption(
        Bucket="tight-bucket",
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]
        },
    )
    s3.put_bucket_versioning(Bucket="tight-bucket", VersioningConfiguration={"Status": "Enabled"})

    ev = S3Security().execute(make_ctx())
    assert ev.status == Status.FAIL
    bad = {
        f.resource
        for f in ev.findings
        if f.severity in (Severity.HIGH, Severity.MEDIUM, Severity.CRITICAL)
    }
    assert "open-bucket" in bad and "tight-bucket" not in bad
    assert ev.data["buckets_examined"] == 2 and ev.data["buckets_without_versioning"] == 1


def test_s3_public_bucket_policy_is_critical():
    # moto does not evaluate IsPublic, so exercise the check against a stub client.
    class Stub:
        def get_public_access_block(self, Bucket):
            return {
                "PublicAccessBlockConfiguration": dict.fromkeys(
                    (
                        "BlockPublicAcls",
                        "IgnorePublicAcls",
                        "BlockPublicPolicy",
                        "RestrictPublicBuckets",
                    ),
                    True,
                )
            }

        def get_bucket_encryption(self, Bucket):
            return {"ServerSideEncryptionConfiguration": {"Rules": [{}]}}

        def get_bucket_policy_status(self, Bucket):
            return {"PolicyStatus": {"IsPublic": True}}

    findings = S3Security._check_bucket(Stub(), "public-bucket")
    assert [(f.resource, f.severity) for f in findings] == [("public-bucket", Severity.CRITICAL)]


def test_s3_unreadable_bucket_settings_are_reported_not_ignored():
    def denied(op):
        return ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, op)

    class Stub:
        def get_public_access_block(self, Bucket):
            raise denied("GetPublicAccessBlock")

        def get_bucket_encryption(self, Bucket):
            raise denied("GetBucketEncryption")

        def get_bucket_policy_status(self, Bucket):
            raise denied("GetBucketPolicyStatus")

    findings = S3Security._check_bucket(Stub(), "locked")
    assert len(findings) == 3 and all(f.severity == Severity.LOW for f in findings)
    assert all("Could not read" in f.message for f in findings)


def test_s3_respects_item_cap(make_ctx, session):
    for i in range(3):
        session.client("s3").create_bucket(Bucket=f"cap-bucket-{i}")
    ev = S3Security().execute(make_ctx(max_items_per_check=2))
    assert ev.data["buckets_examined"] == 2 and ev.data["truncated"] is True


# ------------------------------------------------------------------- CloudTrail
def _trail(session, name="main", **kw):
    session.client("s3").create_bucket(Bucket=f"{name}-logs")
    ct = session.client("cloudtrail")
    ct.create_trail(Name=name, S3BucketName=f"{name}-logs", **kw)
    return ct


def test_cloudtrail_none_configured_is_critical(make_ctx):
    ev = CloudTrail().execute(make_ctx())
    assert ev.status == Status.FAIL and ev.findings[0].severity == Severity.CRITICAL


def test_cloudtrail_stopped_single_region_trail_fails(make_ctx, session):
    _trail(session)
    ev = CloudTrail().execute(make_ctx())
    assert ev.status == Status.FAIL
    text = " ".join(messages(ev))
    assert "logging is stopped" in text and "validation is disabled" in text


def test_cloudtrail_compliant_trail_passes(make_ctx, session):
    ct = _trail(session, IsMultiRegionTrail=True, EnableLogFileValidation=True)
    ct.start_logging(Name="main")
    ev = CloudTrail().execute(make_ctx())
    assert ev.status == Status.PASS and ev.data["compliant_trails"] == 1
    assert ev.data["trails"][0]["log_file_validation"] is True


# -------------------------------------------------------------------------- KMS
def test_kms_rotation_flags_non_rotating_customer_key(make_ctx, session):
    kms = session.client("kms")
    bad = kms.create_key(Description="no rotation")["KeyMetadata"]["KeyId"]
    good = kms.create_key(Description="rotating")["KeyMetadata"]["KeyId"]
    kms.enable_key_rotation(KeyId=good)
    ev = KmsRotation().execute(make_ctx())
    assert ev.status == Status.FAIL
    assert ev.data["keys_examined"] == 2 and ev.data["keys_rotating"] == 1
    assert bad in ev.findings[0].resource


def test_kms_no_customer_keys_is_not_applicable(make_ctx):
    assert KmsRotation().execute(make_ctx()).status == Status.NOT_APPLICABLE


# --------------------------------------------------------- encryption at rest
def test_encryption_at_rest_ebs_default_and_rds(make_ctx, session):
    ev = EncryptionAtRest().execute(make_ctx())
    assert ev.status == Status.FAIL and ev.data["ebs_encryption_by_default"] is False

    session.client("ec2").enable_ebs_encryption_by_default()
    rds = session.client("rds")
    rds.create_db_instance(
        DBInstanceIdentifier="plain-db",
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        MasterUsername="admin",
        MasterUserPassword="Aa1!aaaaaaaaaaaa",
        AllocatedStorage=20,
        StorageEncrypted=False,
    )
    rds.create_db_instance(
        DBInstanceIdentifier="enc-db",
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        MasterUsername="admin",
        MasterUserPassword="Aa1!aaaaaaaaaaaa",
        AllocatedStorage=20,
        StorageEncrypted=True,
    )
    ev = EncryptionAtRest().execute(make_ctx())
    assert ev.data == {"ebs_encryption_by_default": True, "rds_instances": 2, "rds_unencrypted": 1}
    assert [f.resource for f in ev.findings] == ["plain-db"]


# --------------------------------------------------------------------- backups
def test_backups_not_applicable_when_nothing_to_back_up(make_ctx):
    assert Backups().execute(make_ctx()).status == Status.NOT_APPLICABLE


def test_backups_retention_threshold(make_ctx, session):
    rds = session.client("rds")
    for name, days in (("short-db", 1), ("long-db", 14)):
        rds.create_db_instance(
            DBInstanceIdentifier=name,
            DBInstanceClass="db.t3.micro",
            Engine="postgres",
            MasterUsername="admin",
            MasterUserPassword="Aa1!aaaaaaaaaaaa",
            AllocatedStorage=20,
            BackupRetentionPeriod=days,
        )
    ev = Backups().execute(make_ctx())
    assert ev.status == Status.FAIL and [f.resource for f in ev.findings] == ["short-db"]
    assert Backups().execute(make_ctx(min_backup_retention_days=1)).status == Status.PASS


# ------------------------------------------------------------------ network
def _sg(session, name, perms):
    ec2 = session.client("ec2")
    vpc = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
    gid = ec2.create_security_group(GroupName=name, Description=name, VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=gid, IpPermissions=perms)
    return gid


def test_network_exposure_ssh_rdp_and_all_traffic(make_ctx, session):
    ssh = _sg(
        session,
        "ssh-open",
        [
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )
    rng = _sg(
        session,
        "range-open",
        [
            {
                "IpProtocol": "tcp",
                "FromPort": 5000,
                "ToPort": 6000,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )
    allt = _sg(session, "all-open", [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    web = _sg(
        session,
        "web",
        [
            {
                "IpProtocol": "tcp",
                "FromPort": 443,
                "ToPort": 443,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )
    internal = _sg(
        session,
        "internal",
        [
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
            }
        ],
    )

    ev = NetworkExposure().execute(make_ctx())
    flagged = {f.resource.split()[0] for f in ev.findings}
    assert {ssh, allt} <= flagged and not ({web, internal} & flagged)
    assert rng not in flagged
    assert ev.status == Status.FAIL and ev.data["exposed_groups"] == 2


def test_network_exposure_ipv6_and_custom_ports(make_ctx, session):
    gid = _sg(
        session,
        "v6",
        [
            {
                "IpProtocol": "tcp",
                "FromPort": 5432,
                "ToPort": 5432,
                "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
            }
        ],
    )
    assert NetworkExposure().execute(make_ctx()).status == Status.PASS
    ev = NetworkExposure().execute(make_ctx(sensitive_ports=(5432,)))
    assert gid in ev.findings[0].resource


# ---------------------------------------------------------- threat detection
def test_threat_detection_guardduty(make_ctx, session):
    ev = ThreatDetection().execute(make_ctx())
    assert ev.status == Status.FAIL and ev.data["guardduty_enabled"] is False
    session.client("guardduty").create_detector(Enable=True)
    ev = ThreatDetection().execute(make_ctx())
    assert ev.status == Status.PASS and ev.data["guardduty_enabled"] is True


def test_threat_detection_securityhub_optional_requirement(make_ctx, session):
    session.client("guardduty").create_detector(Enable=True)
    assert ThreatDetection().execute(make_ctx()).status == Status.PASS
    strict = ThreatDetection().execute(make_ctx(require_securityhub=True))
    assert strict.status == Status.FAIL and strict.data["securityhub_enabled"] is False
    session.client("securityhub").enable_security_hub()
    assert ThreatDetection().execute(make_ctx(require_securityhub=True)).status == Status.PASS


# -------------------------------------------------------------------- config
def test_config_recorder_absent_stopped_recording(make_ctx, session):
    assert ConfigRecorder().execute(make_ctx()).status == Status.FAIL
    cfg = session.client("config")
    session.client("s3").create_bucket(Bucket="cfg-bucket")
    role = session.client("iam").create_role(RoleName="cfg", AssumeRolePolicyDocument="{}")["Role"][
        "Arn"
    ]
    cfg.put_configuration_recorder(
        ConfigurationRecorder={
            "name": "default",
            "roleARN": role,
            "recordingGroup": {"allSupported": True},
        }
    )
    cfg.put_delivery_channel(DeliveryChannel={"name": "default", "s3BucketName": "cfg-bucket"})
    stopped = ConfigRecorder().execute(make_ctx())
    assert stopped.status == Status.FAIL and "not recording" in messages(stopped)[0]
    cfg.start_configuration_recorder(ConfigurationRecorderName="default")
    ok = ConfigRecorder().execute(make_ctx())
    assert ok.status == Status.PASS and ok.data["recording"] == 1


# ----------------------------------------------------------------- flow logs
def test_vpc_flow_logs(make_ctx, session):
    ec2 = session.client("ec2")
    vpc = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
    ev = VpcFlowLogs().execute(make_ctx())
    assert ev.status == Status.FAIL and vpc in ev.findings[0].resource
    session.client("s3").create_bucket(Bucket="flow-logs-bucket")
    ec2.create_flow_logs(
        ResourceIds=[vpc],
        ResourceType="VPC",
        TrafficType="ALL",
        LogDestinationType="s3",
        LogDestination="arn:aws:s3:::flow-logs-bucket",
    )
    assert VpcFlowLogs().execute(make_ctx()).status == Status.PASS


# ------------------------------------------------------------ error handling
def test_access_denied_becomes_error_evidence_not_a_pass(make_ctx, monkeypatch):
    def deny(self, *a, **k):
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "not allowed"}},
            "GetAccountPasswordPolicy",
        )

    monkeypatch.setattr(IamPasswordPolicy, "collect", deny)
    ev = IamPasswordPolicy().execute(make_ctx())
    assert ev.status == Status.ERROR and "AccessDenied" in ev.summary and ev.verify()


def test_unexpected_client_error_in_collector_is_error(make_ctx, session, monkeypatch):
    client = boto3.client("iam")
    assert client is not None

    def boom(self, ctx):
        raise KeyError("Missing")

    monkeypatch.setattr(IamMfa, "collect", boom)
    ev = IamMfa().execute(make_ctx())
    assert ev.status == Status.ERROR and "KeyError" in ev.summary


@pytest.mark.parametrize(
    "region,partition",
    [("us-east-1", "aws"), ("us-gov-west-1", "aws-us-gov"), ("cn-north-1", "aws-cn")],
)
def test_partition_detection(make_ctx, region, partition):
    assert make_ctx(region).partition == partition


# ------------------------------------------- an item cap must never read as a clean pass
def test_kms_scan_cut_short_by_the_cap_is_incomplete_not_pass(make_ctx, session):
    kms = session.client("kms")
    for _ in range(3):
        key_id = kms.create_key()["KeyMetadata"]["KeyId"]
        kms.enable_key_rotation(KeyId=key_id)

    complete = KmsRotation().execute(make_ctx())
    assert complete.status == Status.PASS

    capped = KmsRotation().execute(make_ctx(max_items_per_check=2))
    assert capped.status == Status.ERROR
    assert capped.data["truncated"] is True
    assert capped.summary.startswith("INCOMPLETE")
    assert any("Incomplete" in f.message for f in capped.findings)


def test_security_groups_scan_cut_short_by_the_cap_is_incomplete_not_pass(make_ctx, session):
    ec2 = session.client("ec2")
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    for i in range(3):
        ec2.create_security_group(GroupName=f"quiet-{i}", Description="d", VpcId=vpc)

    assert NetworkExposure().execute(make_ctx()).status == Status.PASS
    capped = NetworkExposure().execute(make_ctx(max_items_per_check=2))
    assert capped.status == Status.ERROR and capped.data["truncated"] is True


def test_cap_reached_exactly_is_not_reported_as_truncated(make_ctx, session):
    kms = session.client("kms")
    for _ in range(2):
        key_id = kms.create_key()["KeyMetadata"]["KeyId"]
        kms.enable_key_rotation(KeyId=key_id)
    ev = KmsRotation().execute(make_ctx(max_items_per_check=2))
    assert ev.status == Status.PASS and "truncated" not in ev.data


def test_findings_still_win_over_the_incomplete_marker(make_ctx, session):
    kms = session.client("kms")
    for _ in range(3):
        kms.create_key()  # rotation off -> real findings
    ev = KmsRotation().execute(make_ctx(max_items_per_check=2))
    assert ev.status == Status.FAIL and ev.data["truncated"] is True
