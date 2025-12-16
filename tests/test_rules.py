from datetime import datetime, timedelta
from rules import SSHBruteForceDetector, SSHUserEnumerationDetector

def make_event(event_type, ip, username=None, seconds_offset=0):
    return {
        "timestamp": datetime.now() + timedelta(seconds=seconds_offset),
        "event_type": event_type,
        "ip": ip,
        "username": username,
    }


def test_bruteforce_detection_triggers():
    detector = SSHBruteForceDetector(threshold=3, time_window_seconds=60)

    ip = "1.1.1.1"

    events = [
        make_event("FAILED_LOGIN", ip),
        make_event("FAILED_LOGIN", ip, seconds_offset=10),
        make_event("FAILED_LOGIN", ip, seconds_offset=20),
    ]

    alert = None
    for event in events:
        alert = detector.process_event(event)

    assert alert is not None
    assert alert["alert_type"] == "SSH_BRUTE_FORCE"
    assert alert["ip"] == ip


def test_user_enumeration_detection_triggers():
    detector = SSHUserEnumerationDetector(threshold=3, time_window_seconds=60)

    ip = "2.2.2.2"

    events = [
        make_event("INVALID_USER", ip, username="admin"),
        make_event("INVALID_USER", ip, username="test", seconds_offset=5),
        make_event("INVALID_USER", ip, username="oracle", seconds_offset=10),
    ]

    alert = None
    for event in events:
        alert = detector.process_event(event)

    assert alert is not None
    assert alert["alert_type"] == "SSH_USER_ENUMERATION"
    assert alert["ip"] == ip
