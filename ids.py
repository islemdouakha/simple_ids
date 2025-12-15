from parser import parse_log_file
from rules import SSHBruteForceDetector

if __name__ == "__main__":
    detector = SSHBruteForceDetector(
        threshold=3,
        time_window_seconds=120
    )

    for event in parse_log_file("samples/auth.log"):
        alert = detector.process_event(event)
        if alert:
            print(
                f"[ALERT] SSH brute-force detected from {alert['ip']} "
                f"({alert['count']} failures in "
                f"{alert['time_window_seconds']} seconds)"
            )
