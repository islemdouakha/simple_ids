import re
from datetime import datetime
from typing import Optional

# =========================
# SSH LOG PATTERNS
# =========================

FAILED_LOGIN_PATTERNS = [
    # Debian / Ubuntu
    re.compile(r"Failed password for (?P<user>\S+) from (?P<ip>\S+)"),
    # Invalid user failed password
    re.compile(r"Failed password for invalid user (?P<user>\S+) from (?P<ip>\S+)"),
    # PAM authentication failure
    re.compile(r"authentication failure.*rhost=(?P<ip>\S+)"),
]

SUCCESSFUL_LOGIN_PATTERNS = [
    re.compile(r"Accepted password for (?P<user>\S+) from (?P<ip>\S+)"),
    re.compile(r"Accepted publickey for (?P<user>\S+) from (?P<ip>\S+)"),
]

INVALID_USER_PATTERNS = [
    re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\S+)"),
]

TIMESTAMP_REGEX = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)"
)


# =========================
# HELPER FUNCTIONS
# =========================

def parse_timestamp(line: str) -> Optional[datetime]:
    match = TIMESTAMP_REGEX.search(line)
    if not match:
        return None

    now = datetime.now()
    timestamp_str = (
        f"{match.group('month')} "
        f"{match.group('day')} "
        f"{match.group('time')} "
        f"{now.year}"
    )

    try:
        return datetime.strptime(timestamp_str, "%b %d %H:%M:%S %Y")
    except ValueError:
        return None


def match_patterns(patterns, line: str):
    for pattern in patterns:
        match = pattern.search(line)
        if match:
            return match
    return None


# =========================
# MAIN PARSER
# =========================

def parse_ssh_log_line(line: str) -> Optional[dict]:
    timestamp = parse_timestamp(line)
    if not timestamp:
        return None

    # FAILED LOGIN
    match = match_patterns(FAILED_LOGIN_PATTERNS, line)
    if match:
        return {
            "timestamp": timestamp,
            "event_type": "FAILED_LOGIN",
            "username": match.groupdict().get("user"),
            "ip": match.group("ip"),
        }

    # INVALID USER
    match = match_patterns(INVALID_USER_PATTERNS, line)
    if match:
        return {
            "timestamp": timestamp,
            "event_type": "INVALID_USER",
            "username": match.group("user"),
            "ip": match.group("ip"),
        }

    # SUCCESSFUL LOGIN
    match = match_patterns(SUCCESSFUL_LOGIN_PATTERNS, line)
    if match:
        return {
            "timestamp": timestamp,
            "event_type": "SUCCESSFUL_LOGIN",
            "username": match.group("user"),
            "ip": match.group("ip"),
        }

    return None


def parse_log_file(path: str):
    with open(path, "r", errors="ignore") as f:
        for line in f:
            event = parse_ssh_log_line(line)
            if event:
                yield event
