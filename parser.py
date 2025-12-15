import re
from datetime import datetime


FAILED_LOGIN_REGEX = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+).*'
    r'Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\S+)'
)

def parse_ssh_log_line(line):

    match = FAILED_LOGIN_REGEX.search(line)
    if not match:
        return None

    now = datetime.now()
    timestamp_str = f"{match.group('month')} {match.group('day')} {match.group('time')} {now.year}"
    timestamp = datetime.strptime(timestamp_str, "%b %d %H:%M:%S %Y")

    return {
        "timestamp": timestamp,
        "event_type": "FAILED_LOGIN",
        "username": match.group("user"),
        "ip": match.group("ip"),
    }

def parse_log_file(path):
    with open(path, "r") as f:
        for line in f:
            event = parse_ssh_log_line(line)
            if event:
                yield event
