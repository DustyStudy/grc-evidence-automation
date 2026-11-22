from __future__ import annotations

from types import SimpleNamespace as NS

import pytest

from grcevidence.collectors.base import Context, Parameters
from grcevidence.collectors.gcp.gcp import GcpFirewallExposure
from grcevidence.models import Severity, Status


class FakeFirewalls:
    def __init__(self, rules):
        self._r = rules

    def list(self, project):
        assert project == "proj-1"
        return iter(self._r)


class FakeClients:
    def __init__(self, rules=()):
        self._f = FakeFirewalls(list(rules))

    def firewalls(self):
        return self._f


def _rule(name, ranges, allowed):
    return NS(name=name, source_ranges=ranges, allowed=allowed, direction="INGRESS", disabled=False)


def _run(*rules):
    ctx = Context(
        "proj-1",
        "global",
        None,
        Parameters(),
        gcp_project="proj-1",
        gcp_clients=FakeClients(rules),
    )
    return GcpFirewallExposure().execute(ctx)


@pytest.mark.parametrize("proto", ["udp", "UDP", "17"])
def test_udp_sensitive_port_open_to_internet_is_high(proto):
    ev = _run(_rule("udp-ssh", ["0.0.0.0/0"], [NS(I_p_protocol=proto, ports=["22"])]))
    assert ev.status == Status.FAIL
    (f,) = ev.findings
    assert f.resource == "udp-ssh" and f.severity == Severity.HIGH
    assert f.message == "Allows sensitive udp ports (or all ports) from 0.0.0.0/0"
    (r,) = ev.data["resources"]
    assert r["compliant"] is False and r["attributes"]["sensitive_tcp_open"] is False


def test_udp_range_covering_sensitive_port_is_a_finding():
    ev = _run(_rule("udp-range", ["::/0"], [NS(ip_protocol="17", ports=["20-30"])]))
    (f,) = ev.findings
    assert f.message == "Allows sensitive udp ports (or all ports) from ::/0"


def test_udp_non_sensitive_port_is_not_a_finding():
    ev = _run(_rule("udp-high", ["0.0.0.0/0"], [NS(I_p_protocol="udp", ports=["443", "40000"])]))
    assert ev.findings == [] and ev.status == Status.PASS
    assert ev.data["resources"][0]["compliant"] is True


def test_udp_all_ports_is_a_finding():
    ev = _run(_rule("udp-any-port", ["0.0.0.0/0"], [NS(I_p_protocol="udp", ports=[])]))
    (f,) = ev.findings
    assert f.severity == Severity.HIGH
    assert f.message == "Allows sensitive udp ports (or all ports) from 0.0.0.0/0"


def test_udp_internal_range_is_not_a_finding():
    ev = _run(_rule("udp-internal", ["10.0.0.0/8"], [NS(I_p_protocol="udp", ports=["22"])]))
    assert ev.findings == [] and ev.status == Status.PASS


def test_tcp_and_udp_on_different_sensitive_ports_report_each_once():
    allowed = [NS(I_p_protocol="tcp", ports=["22"]), NS(I_p_protocol="udp", ports=["3389"])]
    ev = _run(_rule("mixed", ["0.0.0.0/0"], allowed))
    assert [(f.resource, f.message, f.severity) for f in ev.findings] == [
        ("mixed", "Allows sensitive tcp ports (or all ports) from 0.0.0.0/0", Severity.HIGH),
        ("mixed", "Allows sensitive udp ports (or all ports) from 0.0.0.0/0", Severity.HIGH),
    ]
    assert ev.data["resources"][0]["attributes"]["sensitive_tcp_open"] is True


def test_each_protocol_is_judged_on_its_own_ports():
    # tcp/443 plus udp/22: only the udp entry hits a sensitive port
    allowed = [NS(I_p_protocol="tcp", ports=["443"]), NS(I_p_protocol="udp", ports=["22"])]
    ev = _run(_rule("mixed", ["0.0.0.0/0"], allowed))
    (f,) = ev.findings
    assert f.message == "Allows sensitive udp ports (or all ports) from 0.0.0.0/0"
    assert ev.data["resources"][0]["attributes"]["sensitive_tcp_open"] is False
