from __future__ import annotations

import socket
from datetime import UTC, datetime

import boto3
import pytest
from moto import mock_aws

from grcevidence import cli, lambda_handler, runner
from grcevidence.collectors.base import Context, Parameters

_real_aws_session = runner.aws_session

ACCOUNT = "123456789012"
NOW = datetime(2026, 9, 20, 6, 0, 0, tzinfo=UTC)


_LOCAL = {"localhost", "127.0.0.1", "::1"}


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Fail loudly if a test leaves the machine. moto intercepts inside botocore, so a real
    socket or DNS lookup means a client escaped the mocks (CI would make the same call)."""
    real_getaddrinfo, real_connect = socket.getaddrinfo, socket.socket.connect

    def getaddrinfo(host, *args, **kwargs):
        if host not in _LOCAL:
            raise RuntimeError(f"test tried a real DNS lookup of {host!r}; stub it")
        return real_getaddrinfo(host, *args, **kwargs)

    def connect(self, address):
        if isinstance(address, tuple) and address[0] not in _LOCAL:
            raise RuntimeError(f"test tried a real connection to {address!r}; stub it")
        return real_connect(self, address)

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    monkeypatch.setattr(socket.socket, "connect", connect)


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
