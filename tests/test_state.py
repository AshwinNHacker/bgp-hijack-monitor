import time

from bgp_hijack_monitor.models import BaselineEntry, EventType, HijackEvent, Severity
from bgp_hijack_monitor.state import StateStore


def make_event(**overrides) -> HijackEvent:
    defaults = dict(
        event_type=EventType.ORIGIN_MISMATCH,
        severity=Severity.CRITICAL,
        prefix="203.0.113.0/24",
        matched_config_prefix="203.0.113.0/24",
        observed_origin_asn=13335,
        expected_origin_asns=[64512],
        as_path=[65000, 13335],
        peer="192.0.2.1",
        collector="rrc00",
        timestamp=time.time(),
        message="test event",
    )
    defaults.update(overrides)
    return HijackEvent(**defaults)


def test_baseline_roundtrip(tmp_path):
    store = StateStore(str(tmp_path / "test.sqlite3"))
    entry = BaselineEntry(
        prefix="203.0.113.0/24", origin_asns=[64512], source="ripestat", last_verified=time.time()
    )
    store.upsert_baseline(entry)
    fetched = store.get_baseline("203.0.113.0/24")
    assert fetched is not None
    assert fetched.origin_asns == [64512]
    assert fetched.source == "ripestat"
    store.close()


def test_baseline_upsert_updates_existing(tmp_path):
    store = StateStore(str(tmp_path / "test.sqlite3"))
    store.upsert_baseline(
        BaselineEntry(
            prefix="203.0.113.0/24", origin_asns=[64512], source="config", last_verified=1.0
        )
    )
    store.upsert_baseline(
        BaselineEntry(
            prefix="203.0.113.0/24",
            origin_asns=[64512, 64513],
            source="ripestat",
            last_verified=2.0,
        )
    )
    fetched = store.get_baseline("203.0.113.0/24")
    assert fetched.origin_asns == [64512, 64513]
    assert fetched.source == "ripestat"
    store.close()


def test_record_and_query_events(tmp_path):
    store = StateStore(str(tmp_path / "test.sqlite3"))
    store.record_event(make_event(severity=Severity.LOW))
    store.record_event(make_event(severity=Severity.CRITICAL))
    all_events = store.recent_events(limit=10)
    assert len(all_events) == 2

    critical_only = store.recent_events(limit=10, min_severity="high")
    assert len(critical_only) == 1
    assert critical_only[0]["severity"] == "critical"
    store.close()


def test_observed_origins_tracking(tmp_path):
    store = StateStore(str(tmp_path / "test.sqlite3"))
    store.note_observed_origin("203.0.113.0/24", 64512)
    store.note_observed_origin("203.0.113.0/24", 13335)
    origins = store.observed_origins("203.0.113.0/24")
    assert origins == {64512, 13335}
    store.close()


def test_all_known_origins(tmp_path):
    store = StateStore(str(tmp_path / "test.sqlite3"))
    store.note_observed_origin("203.0.113.0/24", 64512)
    store.note_observed_origin("198.51.100.0/24", 64513)
    known = store.all_known_origins()
    assert known["203.0.113.0/24"] == {64512}
    assert known["198.51.100.0/24"] == {64513}
    store.close()
