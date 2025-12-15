from parser import parse_log_file
from rules import SSHBruteForceDetector
from config import load_config

if __name__ == "__main__":
    config = load_config()

    detector = SSHBruteForceDetector(
        threshold=config["threshold"],
        time_window_seconds=config["time_window_seconds"],
        cooldown_seconds=config["cooldown_seconds"],
    )

    for event in parse_log_file("samples/auth.log"):
        alert = detector.process_event(event)
        if alert:
            print(
                f"[ALERT] SSH brute-force detected from {alert['ip']} "
                f"({alert['count']} failures in "
                f"{alert['time_window_seconds']} seconds)"
            )
