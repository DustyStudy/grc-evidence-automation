"""gcp.firewall_exposure judges source ranges by coverage, not by exact string."""

from __future__ import annotations

from types import SimpleNamespace as NS

import pytest

from grcevidence.collectors.base import Context, Parameters
from grcevidence.collectors.gcp.gcp import GcpFirewallExposure
from grcevidence.models import Severity, Status


def _run(ranges, proto="tcp"):
    rule = NS(
        name="fw",
        source_ranges=ranges,
        allowed=[NS(I_p_protocol=proto, ports=[] if proto == "all" else ["22"])],
        direction="INGRESS",
        disabled=False,
    )
    clients = NS(firewalls=lambda: NS(list=lambda project: iter([rule])))
    ctx = Context("proj-1", "global", None, Parameters(), gcp_project="proj-1", gcp_clients=clients)
    return GcpFirewallExposure().execute(ctx)


@pytest.mark.parametrize(
    "ranges,src",
    [
        (["0.0.0.0/1", "128.0.0.0/1"], "0.0.0.0/0"),
        (["0.0.0.0/2", "64.0.0.0/2", "128.0.0.0/1", "10.0.0.0/8"], "0.0.0.0/0"),
        (["::/1", "8000::/1"], "::/0"),
        (["0::/0"], "::/0"),
        (["0:0:0:0:0:0:0:0/0"], "::/0"),
        (["1.2.3.4/0"], "0.0.0.0/0"),
        (["0.0.0.0/1", "128.0.0.0/1", "0::/0"], "0.0.0.0/0 and ::/0"),
        (["0.0.0.0/0"], "0.0.0.0/0"),  # exact forms keep their wording
        (["0.0.0.0/0", "::/0"], "0.0.0.0/0 and ::/0"),
    ],
)
def test_ranges_covering_a_whole_family_are_internet_open(ranges, src):
    ev = _run(ranges)
    assert ev.status == Status.FAIL
    (f,) = ev.findings
    assert f.message == f"Allows sensitive tcp ports (or all ports) from {src}"
    assert f.severity == Severity.HIGH
    assert ev.data["resources"][0]["attributes"]["open_to_internet"] is True


def test_split_ranges_with_all_protocols_is_critical():
    (f,) = _run(["0.0.0.0/1", "128.0.0.0/1"], proto="all").findings
    assert f.severity == Severity.CRITICAL and f.message == "Allows ALL protocols from 0.0.0.0/0"


@pytest.mark.parametrize("ranges", [["0.0.0.0/1"], ["0.0.0.0/1", "8000::/1"], ["128.0.0.0/1"], []])
def test_partial_coverage_is_not_internet_open(ranges):
    ev = _run(ranges)
    assert ev.status == Status.PASS and ev.findings == []


def test_malformed_source_range_is_an_error_not_a_pass():
    assert _run(["not-a-cidr"]).status == Status.ERROR
