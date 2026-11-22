"""CIDR helpers shared by the AWS and GCP network-exposure collectors."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from typing import Any


def internet_ranges(cidrs: Iterable[Any]) -> list[str]:
    """The whole-family ranges ("0.0.0.0/0", "::/0") the CIDRs together collapse to, so
    "0.0.0.0/1" plus "128.0.0.0/1" counts; empty when neither family is fully covered.
    A malformed CIDR raises ValueError, which the base class records as ERROR rather than
    reading it as "not open"."""
    nets = [ipaddress.ip_network(str(c).strip(), strict=False) for c in cidrs]
    out: list[str] = []
    for version in (4, 6):
        family: list[Any] = [n for n in nets if n.version == version]
        out += [str(n) for n in ipaddress.collapse_addresses(family) if n.prefixlen == 0]
    return out
