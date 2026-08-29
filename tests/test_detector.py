import time

from bgp_hijack_monitor.config import MonitoredPrefix
from bgp_hijack_monitor.detector import evaluate_update, match_config_prefix
from bgp_hijack_monitor.models import BgpUpdate, EventType, Severity

NOW = time.time()


def make_prefix(**overrides) -> MonitoredPrefix:
    defaults = dict(
        prefix="203.0.113.0/24",
        expected_origin_asns=[64512],
        description="test",
        allowed_more_specific_asns=[],
        min_expected_path_length=1,
    )
    defaults.update(overrides)
    return MonitoredPrefix(**defaults)


def make_update(**overrides) -> BgpUpdate:
    defaults = dict(
        raw_prefix="203.0.113.0/24",
        announced=True,
        as_path=[65000, 64512],
        origin_asn=64512,
        peer="192.0.2.1",
        collector="rrc00",
        timestamp=NOW,
    )
    defaults.update(overrides)
    return BgpUpdate(**defaults)


# --------------------------------------------------------------------------
# match_config_prefix
# --------------------------------------------------------------------------

def test_match_exact_prefix():
    configured = [make_prefix()]
    update = make_update(raw_prefix="203.0.113.0/24")
    assert match_config_prefix(update, configured).prefix == "203.0.113.0/24"


def test_match_more_specific_prefix():
    configured = [make_prefix()]
    update = make_update(raw_prefix="203.0.113.128/25")
    assert match_config_prefix(update, configured).prefix == "203.0.113.0/24"


def test_match_none_for_unrelated_prefix():
    configured = [make_prefix()]
    update = make_update(raw_prefix="198.51.100.0/24")
    assert match_config_prefix(update, configured) is None


def test_match_picks_most_specific_parent():
    configured = [
        make_prefix(prefix="203.0.113.0/24"),
        make_prefix(prefix="203.0.113.0/25", expected_origin_asns=[64513]),
    ]
    update = make_update(raw_prefix="203.0.113.10/32")
    matched = match_config_prefix(update, configured)
    assert matched.prefix == "203.0.113.0/25"


# --------------------------------------------------------------------------
# Rule 1: origin mismatch (classic hijack)
# --------------------------------------------------------------------------

def test_legit_announcement_no_events_flagged():
    configured = [make_prefix()]
    update = make_update(origin_asn=64512)
    events = evaluate_update(update, configured)
    types = [e.event_type for e in events]
    assert EventType.ORIGIN_MISMATCH not in types
    assert EventType.NEW_ANNOUNCEMENT_OK in types


def test_origin_mismatch_detected():
    configured = [make_prefix(expected_origin_asns=[64512])]
    update = make_update(origin_asn=13335, as_path=[65000, 13335])  # attacker AS
    events = evaluate_update(update, configured)
    hijack_events = [e for e in events if e.event_type == EventType.ORIGIN_MISMATCH]
    assert len(hijack_events) == 1
    event = hijack_events[0]
    assert event.severity == Severity.CRITICAL
    assert event.observed_origin_asn == 13335
    assert event.expected_origin_asns == [64512]


def test_multiple_expected_origins_no_false_positive():
    configured = [make_prefix(expected_origin_asns=[64512, 64513])]
    update = make_update(origin_asn=64513)
    events = evaluate_update(update, configured)
    assert not any(e.event_type == EventType.ORIGIN_MISMATCH for e in events)


# --------------------------------------------------------------------------
# Rule 2: sub-prefix hijack
# --------------------------------------------------------------------------

def test_subprefix_hijack_detected():
    configured = [make_prefix(prefix="203.0.113.0/24", expected_origin_asns=[64512])]
    update = make_update(
        raw_prefix="203.0.113.128/25", origin_asn=13335, as_path=[65000, 13335]
    )
    events = evaluate_update(update, configured)
    sub_events = [e for e in events if e.event_type == EventType.UNAUTHORIZED_SUBPREFIX]
    assert len(sub_events) == 1
    assert sub_events[0].severity == Severity.CRITICAL
    assert sub_events[0].prefix == "203.0.113.128/25"


def test_subprefix_by_allowed_asn_not_flagged():
    configured = [
        make_prefix(
            prefix="203.0.113.0/24",
            expected_origin_asns=[64512],
            allowed_more_specific_asns=[13335],  # e.g. a scrubbing provider
        )
    ]
    update = make_update(raw_prefix="203.0.113.128/25", origin_asn=13335)
    events = evaluate_update(update, configured)
    assert not any(e.event_type == EventType.UNAUTHORIZED_SUBPREFIX for e in events)


def test_subprefix_by_expected_origin_not_flagged():
    configured = [make_prefix(prefix="203.0.113.0/24", expected_origin_asns=[64512])]
    update = make_update(raw_prefix="203.0.113.128/25", origin_asn=64512)
    events = evaluate_update(update, configured)
    assert not any(e.event_type == EventType.UNAUTHORIZED_SUBPREFIX for e in events)


# --------------------------------------------------------------------------
# Rule 3: MOAS conflict
# --------------------------------------------------------------------------

def test_moas_conflict_when_legit_and_attacker_both_seen():
    configured = [make_prefix(expected_origin_asns=[64512])]
    update = make_update(origin_asn=13335, as_path=[65000, 13335])
    known_origins = {"203.0.113.0/24": {64512}}  # legit origin also currently seen
    events = evaluate_update(update, configured, known_origins=known_origins)
    moas_events = [e for e in events if e.event_type == EventType.MOAS_CONFLICT]
    assert len(moas_events) == 1
    assert moas_events[0].severity == Severity.CRITICAL


def test_origin_mismatch_not_moas_when_legit_not_seen():
    configured = [make_prefix(expected_origin_asns=[64512])]
    update = make_update(origin_asn=13335)
    known_origins = {"203.0.113.0/24": {13335}}  # only attacker seen so far
    events = evaluate_update(update, configured, known_origins=known_origins)
    assert any(e.event_type == EventType.ORIGIN_MISMATCH for e in events)
    assert not any(e.event_type == EventType.MOAS_CONFLICT for e in events)


# --------------------------------------------------------------------------
# Rule 4: suspicious path length
# --------------------------------------------------------------------------

def test_short_path_flagged_when_min_configured():
    configured = [
        make_prefix(expected_origin_asns=[64512], min_expected_path_length=3)
    ]
    update = make_update(origin_asn=64512, as_path=[64512])  # path length 1 < 3
    events = evaluate_update(update, configured)
    assert any(e.event_type == EventType.SUSPICIOUS_PATH_LENGTH for e in events)


def test_short_path_not_flagged_by_default():
    configured = [make_prefix(expected_origin_asns=[64512])]  # min_expected_path_length=1
    update = make_update(origin_asn=64512, as_path=[64512])
    events = evaluate_update(update, configured)
    assert not any(e.event_type == EventType.SUSPICIOUS_PATH_LENGTH for e in events)


# --------------------------------------------------------------------------
# Withdrawals
# --------------------------------------------------------------------------

def test_withdrawal_of_monitored_prefix_is_low_severity_info():
    configured = [make_prefix()]
    update = make_update(announced=False, origin_asn=None, as_path=[])
    events = evaluate_update(update, configured)
    assert len(events) == 1
    assert events[0].event_type == EventType.ROUTE_WITHDRAWN
    assert events[0].severity == Severity.LOW


def test_withdrawal_of_unrelated_prefix_ignored():
    configured = [make_prefix()]
    update = make_update(raw_prefix="198.51.100.0/24", announced=False, origin_asn=None, as_path=[])
    events = evaluate_update(update, configured)
    assert events == []


def test_unrelated_prefix_produces_no_events():
    configured = [make_prefix()]
    update = make_update(raw_prefix="198.51.100.0/24", origin_asn=64512)
    events = evaluate_update(update, configured)
    assert events == []
