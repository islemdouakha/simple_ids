import re
from datetime import datetime


FAILED_LOGIN_REGEX = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+).*'
    r'Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\S+)'
)

SUCCESS_LOGIN_REGEX = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+).*'
    r'Accepted password for (?P<user>\S+) from (?P<ip>\S+)'
)

INVALID_USER_REGEX = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+).*'
    r'Invalid user (?P<user>\S+) from (?P<ip>\S+)'
)


def parse_ssh_log_line(line):
    """
    Parse a single SSH log line.
    Returns a dict if the line matches a known pattern, otherwise None.
    """
    now = datetime.now()

    failed_match = FAILED_LOGIN_REGEX.search(line)
    if failed_match:
        timestamp_str = (
            f"{failed_match.group('month')} "
            f"{failed_match.group('day')} "
            f"{failed_match.group('time')} "
            f"{now.year}"
        )
        timestamp = datetime.strptime(timestamp_str, "%b %d %H:%M:%S %Y")

        return {
            "timestamp": timestamp,
            "event_type": "FAILED_LOGIN",
            "username": failed_match.group("user"),
            "ip": failed_match.group("ip"),
        }

    success_match = SUCCESS_LOGIN_REGEX.search(line)
    if success_match:
        timestamp_str = (
            f"{success_match.group('month')} "
            f"{success_match.group('day')} "
            f"{success_match.group('time')} "
            f"{now.year}"
        )
        timestamp = datetime.strptime(timestamp_str, "%b %d %H:%M:%S %Y")

        return {
            "timestamp": timestamp,
            "event_type": "SUCCESSFUL_LOGIN",
            "username": success_match.group("user"),
            "ip": success_match.group("ip"),
        }
    
    invalid_match = INVALID_USER_REGEX.search(line)
    if invalid_match:
        timestamp_str = (
            f"{invalid_match.group('month')} "
            f"{invalid_match.group('day')} "
            f"{invalid_match.group('time')} "
            f"{now.year}"
        )
        timestamp = datetime.strptime(timestamp_str, "%b %d %H:%M:%S %Y")

        return {
            "timestamp": timestamp,
            "event_type": "INVALID_USER",
            "username": invalid_match.group("user"),
            "ip": invalid_match.group("ip"),
        }

    return None

def parse_log_file(path):
    with open(path, "r") as f:
        for line in f:
            event = parse_ssh_log_line(line)
            if event:
                yield event
