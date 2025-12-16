from parser import parse_ssh_log_line

def test_failed_login_parsing():
    line = "Jan 12 10:00:01 server sshd[1]: Failed password for root from 1.1.1.1"
    event = parse_ssh_log_line(line)

    assert event is not None
    assert event["event_type"] == "FAILED_LOGIN"
    assert event["username"] == "root"
    assert event["ip"] == "1.1.1.1"


def test_invalid_user_parsing():
    line = "Jan 12 10:00:02 server sshd[2]: Invalid user admin from 2.2.2.2"
    event = parse_ssh_log_line(line)

    assert event is not None
    assert event["event_type"] == "INVALID_USER"
    assert event["username"] == "admin"
    assert event["ip"] == "2.2.2.2"


def test_successful_login_parsing():
    line = "Jan 12 10:00:03 server sshd[3]: Accepted password for user from 3.3.3.3"
    event = parse_ssh_log_line(line)

    assert event is not None
    assert event["event_type"] == "SUCCESSFUL_LOGIN"
    assert event["username"] == "user"
    assert event["ip"] == "3.3.3.3"


def test_unrelated_log_is_ignored():
    line = "Jan 12 10:00:04 server kernel: CPU temperature normal"
    event = parse_ssh_log_line(line)

    assert event is None

def test_missing_timestamp_is_ignored():
    line = "sshd[123]: Failed password for root from 1.1.1.1"
    event = parse_ssh_log_line(line)
    assert event is None


def test_malformed_timestamp_is_ignored():
    line = "FooBar Invalid user admin from 2.2.2.2"
    event = parse_ssh_log_line(line)
    assert event is None


def test_unmatched_ssh_line_is_ignored():
    line = "Jan 12 10:00:01 server sshd[1]: Connection closed by 1.1.1.1"
    event = parse_ssh_log_line(line)
    assert event is None
