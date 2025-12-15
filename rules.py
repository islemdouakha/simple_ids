from collections import defaultdict
from datetime import timedelta

class SSHBruteForceDetector:
    def __init__(self, threshold=5, time_window_seconds=120, cooldown_seconds=300):
        self.threshold = threshold
        self.time_window = timedelta(seconds=time_window_seconds)
        self.cooldown = timedelta(seconds=cooldown_seconds)

        self.failed_attempts = defaultdict(list)
        self.last_alert_time = {}

    def process_event(self, event):
        """
        Process a single event.
        Returns an alert dict if brute-force is detected, otherwise None.
        """
        if event["event_type"] != "FAILED_LOGIN":
            return None

        ip = event["ip"]
        timestamp = event["timestamp"]

        # Store timestamp
        self.failed_attempts[ip].append(timestamp)

        # Keep only attempts within time window
        self.failed_attempts[ip] = [
            t for t in self.failed_attempts[ip]
            if timestamp - t <= self.time_window
        ]

        # Check brute-force threshold
        if len(self.failed_attempts[ip]) >= self.threshold:

            # Check cooldown
            last_alert = self.last_alert_time.get(ip)
            if last_alert and (timestamp - last_alert) < self.cooldown:
                return None  # Suppress duplicate alert

            # Register alert time
            self.last_alert_time[ip] = timestamp

            return {
                "alert_type": "SSH_BRUTE_FORCE",
                "ip": ip,
                "count": len(self.failed_attempts[ip]),
                "time_window_seconds": self.time_window.seconds,
                "cooldown_seconds": self.cooldown.seconds,
                "last_seen": timestamp,
            }

        return None
