from bgp_hijack_monitor.utils import (
    is_strict_subprefix_of,
    is_subprefix_of,
    prefix_length,
)


def test_is_subprefix_of_exact_match():
    assert is_subprefix_of("203.0.113.0/24", "203.0.113.0/24") is True


def test_is_subprefix_of_more_specific():
    assert is_subprefix_of("203.0.113.128/25", "203.0.113.0/24") is True


def test_is_subprefix_of_unrelated():
    assert is_subprefix_of("198.51.100.0/24", "203.0.113.0/24") is False


def test_is_subprefix_of_less_specific_is_false():
    # a /23 is NOT a subprefix of a /24 inside it (wrong direction)
    assert is_subprefix_of("203.0.113.0/23", "203.0.113.0/24") is False


def test_is_strict_subprefix_excludes_exact():
    assert is_strict_subprefix_of("203.0.113.0/24", "203.0.113.0/24") is False
    assert is_strict_subprefix_of("203.0.113.0/25", "203.0.113.0/24") is True


def test_ipv6_subprefix():
    assert is_subprefix_of("2001:db8:1::/48", "2001:db8::/32") is True
    assert is_subprefix_of("2001:db9::/32", "2001:db8::/32") is False


def test_prefix_length():
    assert prefix_length("203.0.113.0/24") == 24
    assert prefix_length("2001:db8::/32") == 32
