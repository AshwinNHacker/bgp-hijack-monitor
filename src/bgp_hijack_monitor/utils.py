"""Small IP-prefix helper utilities used across the project."""

from __future__ import annotations

import ipaddress


def parse_network(prefix: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    return ipaddress.ip_network(prefix, strict=False)


def is_subprefix_of(candidate: str, parent: str) -> bool:
    """True if `candidate` is the same as, or a more-specific subnet of, `parent`."""
    cand_net = parse_network(candidate)
    parent_net = parse_network(parent)
    if cand_net.version != parent_net.version:
        return False
    return cand_net.subnet_of(parent_net) or cand_net == parent_net


def is_strict_subprefix_of(candidate: str, parent: str) -> bool:
    """True if `candidate` is a *strictly more specific* subnet of `parent`."""
    cand_net = parse_network(candidate)
    parent_net = parse_network(parent)
    if cand_net.version != parent_net.version:
        return False
    return cand_net != parent_net and cand_net.subnet_of(parent_net)


def prefix_length(prefix: str) -> int:
    return parse_network(prefix).prefixlen
