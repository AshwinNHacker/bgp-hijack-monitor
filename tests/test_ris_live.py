import json

from bgp_hijack_monitor.ris_live import RisLiveClient, _parse_as_path


def make_client() -> RisLiveClient:
    return RisLiveClient(prefixes=["203.0.113.0/24"])


def test_parse_as_path_simple():
    assert _parse_as_path([65000, 65001, 64512]) == [65000, 65001, 64512]


def test_parse_as_path_with_as_set():
    # RIS Live represents AS_SET segments as nested lists
    assert _parse_as_path([65000, [65001, 65002], 64512]) == [65000, 65001, 64512]


def test_parse_as_path_empty():
    assert _parse_as_path([]) == []
    assert _parse_as_path(None) == []


def test_parse_message_announcement():
    client = make_client()
    raw = json.dumps(
        {
            "type": "ris_message",
            "data": {
                "peer": "192.0.2.1",
                "host": "rrc00",
                "timestamp": 1700000000.0,
                "path": [65000, 64512],
                "community": [[64512, 100]],
                "announcements": [
                    {"next_hop": "192.0.2.1", "prefixes": ["203.0.113.0/24"]}
                ],
            },
        }
    )
    updates = client._parse_message(raw)
    assert len(updates) == 1
    u = updates[0]
    assert u.raw_prefix == "203.0.113.0/24"
    assert u.announced is True
    assert u.as_path == [65000, 64512]
    assert u.origin_asn == 64512
    assert u.peer == "192.0.2.1"
    assert u.community == ["64512:100"]


def test_parse_message_withdrawal():
    client = make_client()
    raw = json.dumps(
        {
            "type": "ris_message",
            "data": {
                "peer": "192.0.2.1",
                "host": "rrc00",
                "timestamp": 1700000000.0,
                "withdrawals": ["203.0.113.0/24"],
            },
        }
    )
    updates = client._parse_message(raw)
    assert len(updates) == 1
    u = updates[0]
    assert u.raw_prefix == "203.0.113.0/24"
    assert u.announced is False
    assert u.origin_asn is None


def test_parse_message_ignores_non_ris_message():
    client = make_client()
    raw = json.dumps({"type": "ris_subscribe_ok", "data": {}})
    assert client._parse_message(raw) == []


def test_parse_message_ignores_invalid_json():
    client = make_client()
    assert client._parse_message("not json{{{") == []


def test_parse_message_multiple_prefixes_in_one_announcement():
    client = make_client()
    raw = json.dumps(
        {
            "type": "ris_message",
            "data": {
                "peer": "192.0.2.1",
                "host": "rrc00",
                "timestamp": 1700000000.0,
                "path": [65000, 64512],
                "announcements": [
                    {
                        "next_hop": "192.0.2.1",
                        "prefixes": ["203.0.113.0/24", "203.0.114.0/24"],
                    }
                ],
            },
        }
    )
    updates = client._parse_message(raw)
    assert len(updates) == 2
    assert {u.raw_prefix for u in updates} == {"203.0.113.0/24", "203.0.114.0/24"}
