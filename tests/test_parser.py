import sys
sys.path.append("src")
from common.parser import parse_message


def env(raw):
    return {"received_at": "2026-10-03T10:15:30+00:00", "source_ip": "10.1.1.1", "raw": raw}


def test_cisco_link_down():
    e = parse_message(env("<187>Oct  3 10:15:22 R1 %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down"))
    assert e["device_name"] == "R1"
    assert e["severity"] == 3 and e["severity_name"] == "error"
    assert e["event_code"] == "LINK-3-UPDOWN"
    assert e["category"] == "link"
    assert e["interface"] == "GigabitEthernet0/1"


def test_firewall_deny():
    e = parse_message(env('<134>devname="FW-HCM-01" type=traffic action=deny srcip=203.0.113.50 dstip=10.0.0.5 dstport=22 proto=6'))
    assert e["device_type"] == "firewall"
    assert e["action"] == "deny"
    assert e["src_ip"] == "203.0.113.50"
    assert e["dst_port"] == 22


def test_login_failed_source():
    e = parse_message(env("<188>Oct  3 10:16:01 SW2 %SEC_LOGIN-4-LOGIN_FAILED: Login failed [user: admin] [Source: 198.51.100.7]"))
    assert e["category"] == "auth"
    assert e["src_ip"] == "198.51.100.7"
    assert e["device_type"] == "switch"


def test_garbage_returns_none():
    assert parse_message(env("hello world")) is None


def test_wrong_timezone_falls_back_to_received_at():
    # Log ghi 23:20:39 nhưng thực tế nhận lúc 16:20:39 UTC (lệch 7 tiếng)
    e = parse_message({
        "received_at": "2026-10-03T16:20:39+00:00",
        "source_ip": "10.1.1.1",
        "raw": "<187>Oct  3 23:20:39 R2 %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down",
    })
    assert e["event_time"] == e["received_at"]


def test_correct_time_is_kept():
    # Log ghi 16:20:36, nhận lúc 16:20:39 (lệch 3 giây) thì giữ giờ trong log
    e = parse_message({
        "received_at": "2026-10-03T16:20:39+00:00",
        "source_ip": "10.1.1.1",
        "raw": "<187>Oct  3 16:20:36 R2 %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down",
    })
    assert e["event_time"].second == 36