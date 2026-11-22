from __future__ import annotations

from types import SimpleNamespace as NS

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


def _rule(name, ranges, allowed, direction="INGRESS", disabled=False):
    return NS(
        name=name, source_ranges=ranges, allowed=allowed, direction=direction, disabled=disabled
    )


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


def _ssh(proto="tcp"):
    return [NS(I_p_protocol=proto, ports=["22"])]


def test_ipv6_any_ssh_is_a_finding():
    ev = _run(_rule("v6-ssh", ["::/0"], _ssh()))
    assert ev.status == Status.FAIL
    (f,) = ev.findings
    assert f.resource == "v6-ssh" and f.severity == Severity.HIGH
    assert f.message == "Allows sensitive tcp ports (or all ports) from ::/0"
    assert ev.data["resources"][0]["attributes"] == {
        "open_to_internet": True,
        "all_protocols": False,
        "sensitive_tcp_open": True,
    }


def test_ipv6_any_all_protocols_is_critical():
    ev = _run(_rule("v6-all", [" ::/0 "], [NS(I_p_protocol="all", ports=[])]))
    (f,) = ev.findings
    assert f.severity == Severity.CRITICAL and f.message == "Allows ALL protocols from ::/0"


def test_protocol_number_6_is_tcp():
    ev = _run(
        _rule("num-ssh", ["0.0.0.0/0"], _ssh("6")),
        _rule("num-any-port", ["::/0"], [NS(ip_protocol="6", ports=[])]),
        _rule("num-range", ["0.0.0.0/0"], [NS(I_p_protocol="6", ports=["20-30"])]),
    )
    assert [f.resource for f in ev.findings] == ["num-ssh", "num-any-port", "num-range"]
    assert {f.severity for f in ev.findings} == {Severity.HIGH}


def test_ipv4_any_still_a_finding_with_unchanged_message():
    ev = _run(_rule("v4-ssh", ["0.0.0.0/0"], _ssh()))
    (f,) = ev.findings
    assert f.message == "Allows sensitive tcp ports (or all ports) from 0.0.0.0/0"


def test_dual_stack_rule_reports_once():
    ev = _run(_rule("dual", ["0.0.0.0/0", "::/0"], _ssh()))
    (f,) = ev.findings
    assert f.message == "Allows sensitive tcp ports (or all ports) from 0.0.0.0/0 and ::/0"


def test_non_findings():
    ev = _run(
        _rule("internal", ["10.0.0.0/8"], _ssh()),
        _rule("internal-v6", ["fd00::/8"], _ssh("6")),
        _rule("egress", ["::/0"], _ssh(), direction="EGRESS"),
        _rule("disabled", ["::/0"], _ssh("6"), disabled=True),
        _rule("web", ["::/0"], [NS(I_p_protocol="6", ports=["443"])]),
        _rule("udp", ["::/0"], [NS(I_p_protocol="17", ports=["22"])]),
    )
    assert ev.findings == [] and ev.status == Status.PASS
    assert all(r["compliant"] for r in ev.data["resources"])
