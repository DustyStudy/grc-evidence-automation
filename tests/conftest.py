from __future__ import annotations

from datetime import UTC, datetime

import boto3
import pytest
from moto import mock_aws

from grcevidence.collectors.base import Context, Parameters

ACCOUNT = "123456789012"
NOW = datetime(2026, 9, 20, 6, 0, 0, tzinfo=UTC)


@pytest.fixture(autouse=True)
def aws_env(monkeypatch):
    for key, val in {
        "AWS_ACCESS_KEY_ID": "testing",
        "AWS_SECRET_ACCESS_KEY": "testing",
        "AWS_SECURITY_TOKEN": "testing",
        "AWS_SESSION_TOKEN": "testing",
        "AWS_DEFAULT_REGION": "us-east-1",
    }.items():
        monkeypatch.setenv(key, val)
    with mock_aws():
        yield


@pytest.fixture
def session():
    return boto3.Session(region_name="us-east-1")


@pytest.fixture
def make_ctx(session):
    def _make(region: str = "us-east-1", **params) -> Context:
        return Context(ACCOUNT, region, session, Parameters(**params), NOW)

    return _make
