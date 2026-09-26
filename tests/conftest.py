from __future__ import annotations

from datetime import UTC, datetime

import boto3
import pytest
from moto import mock_aws

from grcevidence import cli, lambda_handler, runner
from grcevidence.collectors.base import Context, Parameters

_real_aws_session = runner.aws_session

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

    # moto only serves the standard AWS hostnames, so sessions built under moto run with FIPS
    # off. tests/test_fips.py exercises the real FIPS behavior.
    def _moto_session(use_fips_endpoint: bool = True, **kwargs):
        return _real_aws_session(False, **kwargs)

    for mod in (runner, cli, lambda_handler):
        monkeypatch.setattr(mod, "aws_session", _moto_session)
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
