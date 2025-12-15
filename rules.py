from collections import defaultdict
from datetime import timedelta

class SSHBruteForceDetector:
    def __init__(self, threshold=5, time_window_seconds=120):
        self.threshold = threshold
        self.time_window = timedelta(seconds=time_window_seconds)
        self.failed_attempts = defaultdict(list)

    def process_event(self, event):
        """
        Process a single event.
        Returns an alert dict if brute-force is detected, otherwise None.
        """
        if event["event_type"] != "FAILED_LOGIN":
            return None

        ip = event["ip"]
        timestamp = event["timestamp"]

        # Store the timestamp
        self.failed_attempts[ip].append(timestamp)

        # Remove events outside the time window
        self.failed_attempts[ip] = [
            t for t in self.failed_attempts[ip]
            if timestamp - t <= self.time_window
        ]

        # Check threshold
        if len(self.failed_attempts[ip]) >= self.threshold:
            return {
                "alert_type": "SSH_BRUTE_FORCE",
                "ip": ip,
                "count": len(self.failed_attempts[ip]),
                "time_window_seconds": self.time_window.seconds,
                "last_seen": timestamp,
            }

        return None
