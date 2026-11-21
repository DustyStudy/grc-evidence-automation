"""aws.secrets_rotation tests.

moto models ListSecrets (RotationEnabled, RotationRules, LastRotatedDate, OwningService) and
RotateSecret without a Lambda, so it covers listing, disabled/enabled rotation, owning
service and the cap. moto stamps LastRotatedDate with the real clock, so those tests set
ctx.now to it. Date-specific metadata (old LastRotatedDate, ScheduleExpression, never
rotated) uses a botocore Stubber so the date math runs against the fixed NOW.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import boto3
import pytest
from botocore.stub import Stubber

from grcevidence.collectors.aws.secrets_rotation import SecretsRotation
from grcevidence.collectors.base import Context, Parameters
from grcevidence.models import Severity, Status
from tests.conftest import ACCOUNT, NOW

ARN = "arn:aws:secretsmanager:us-east-1:123456789012:secret:db-AbCdEf"


def _ctx(session, now: datetime | None = None, **params) -> Context:
    return Context(ACCOUNT, "us-east-1", session, Parameters(**params), now or datetime.now(UTC))


def test_no_secrets_is_not_applicable(make_ctx):
    ev = SecretsRotation().execute(make_ctx())
    assert ev.status == Status.NOT_APPLICABLE and ev.data["resources"] == []


def test_disabled_rotation_flagged_without_recording_values(session):
    sm = session.client("secretsmanager")
    arn = sm.create_secret(
        Name="app/db", SecretString="hunter2-value", Tags=[{"Key": "team", "Value": "tag-val"}]
    )["ARN"]
    ev = SecretsRotation().execute(_ctx(session))
    (finding,) = ev.findings
    assert finding.resource == arn and finding.severity == Severity.MEDIUM
    (res,) = ev.data["resources"]
    assert res["type"] == "AWS::SecretsManager::Secret" and not res["compliant"]
    assert res["attributes"] == {
        "rotation_enabled": False,
        "rotation_days": None,
        "last_rotated": None,
        "days_since_rotation": 0,
        "owning_service": None,
    }
    dumped = json.dumps(ev.to_dict(), default=str)
    assert "hunter2-value" not in dumped and "tag-val" not in dumped


def test_rotation_interval_judged_against_max(session):
    sm = session.client("secretsmanager")
    ok = sm.create_secret(Name="ok", SecretString="x")["ARN"]
    slow = sm.create_secret(Name="slow", SecretString="x")["ARN"]
    sm.rotate_secret(SecretId=ok, RotationRules={"AutomaticallyAfterDays": 30})
    sm.rotate_secret(SecretId=slow, RotationRules={"AutomaticallyAfterDays": 180})
    ev = SecretsRotation().execute(_ctx(session))
    assert [(f.resource, f.severity) for f in ev.findings] == [(slow, Severity.LOW)]
    res = {r["id"]: r for r in ev.data["resources"]}
    assert res[ok]["compliant"] and res[ok]["attributes"]["rotation_days"] == 30
    assert res[ok]["attributes"]["last_rotated"] is not None
    assert SecretsRotation().execute(_ctx(session, max_secret_rotation_days=365)).status == (
        Status.PASS
    )


def test_service_owned_secret_names_the_owner(session):
    sm = session.client("secretsmanager")
    sm.create_secret(
        Name="rds!db-1",
        SecretString="x",
        Tags=[{"Key": "aws:secretsmanager:owningService", "Value": "rds"}],
    )
    ev = SecretsRotation().execute(_ctx(session))
    (finding,) = ev.findings
    assert "managed by rds" in finding.message
    assert ev.data["resources"][0]["attributes"]["owning_service"] == "rds"


def test_cap_marks_record_incomplete(session):
    sm = session.client("secretsmanager")
    sm.create_secret(Name="a", SecretString="x")
    sm.create_secret(Name="b", SecretString="x")
    ev = SecretsRotation().execute(_ctx(session, max_items_per_check=1))
    # Rotation is off on both, so the examined one fails; the cap must still be recorded.
    assert ev.status == Status.FAIL and ev.data["truncated"]
    assert any("Incomplete" in f.message for f in ev.findings)
    assert len(ev.data["resources"]) == 1


def _run_stubbed(entry: dict) -> object:
    client = boto3.client("secretsmanager", region_name="us-east-1")
    stub = Stubber(client)
    stub.add_response("list_secrets", {"SecretList": [{"ARN": ARN, "Name": "db", **entry}]}, {})

    class _Session:
        def client(self, *_args, **_kwargs):
            return client

    with stub:
        return SecretsRotation().execute(
            Context(ACCOUNT, "us-east-1", _Session(), Parameters(), NOW)
        )


@pytest.mark.parametrize(
    ("entry", "expected", "days", "age"),
    [
        # Enabled on a 30-day schedule but untouched for 120 days: rotation is failing.
        (
            {
                "RotationEnabled": True,
                "RotationRules": {"AutomaticallyAfterDays": 30},
                "LastRotatedDate": NOW - timedelta(days=120),
            },
            [Severity.MEDIUM],
            30,
            120,
        ),
        # 180-day schedule rotated 100 days ago: over policy (LOW) but not failing.
        (
            {
                "RotationEnabled": True,
                "RotationRules": {"ScheduleExpression": "rate(180 days)"},
                "LastRotatedDate": NOW - timedelta(days=100),
            },
            [Severity.LOW],
            180,
            100,
        ),
        # Hourly rate, never rotated: age counts from creation.
        (
            {
                "RotationEnabled": True,
                "RotationRules": {"ScheduleExpression": "rate(12 hours)"},
                "CreatedDate": NOW - timedelta(days=200),
            },
            [Severity.MEDIUM],
            1,
            200,
        ),
        # cron() has no fixed interval; only staleness is judged.
        (
            {
                "RotationEnabled": True,
                "RotationRules": {"ScheduleExpression": "cron(0 4 1 * ? *)"},
                "LastRotatedDate": NOW - timedelta(days=20),
            },
            [],
            None,
            20,
        ),
        # No dates at all: nothing to age.
        ({"RotationEnabled": True, "RotationRules": {}}, [], None, None),
    ],
)
def test_stubbed_schedules_and_staleness(entry, expected, days, age):
    ev = _run_stubbed(entry)
    assert [f.severity for f in ev.findings] == expected
    attrs = ev.data["resources"][0]["attributes"]
    assert attrs["rotation_days"] == days and attrs["days_since_rotation"] == age


def test_parameters_accept_and_validate_new_fields():
    params = Parameters.from_dict(
        {"max_secret_rotation_days": 30, "min_certificate_days_remaining": 14}
    )
    assert params.max_secret_rotation_days == 30 and params.min_certificate_days_remaining == 14
    assert Parameters().max_secret_rotation_days == 90
    assert Parameters().min_certificate_days_remaining == 30
    for key in ("max_secret_rotation_days", "min_certificate_days_remaining"):
        for bad in (-1, "30", True):
            with pytest.raises(ValueError, match=key):
                Parameters.from_dict({key: bad})
