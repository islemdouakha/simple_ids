from parser import parse_log_file
from rules import SSHBruteForceDetector, SSHUserEnumerationDetector
from config import load_config
from mitre import enrich_alert_with_mitre
import json

if __name__ == "__main__":
    config = load_config()
    log_path = config["log_path"]

    all_alerts = []
    brute_force = SSHBruteForceDetector(
        threshold=config["threshold"],
        time_window_seconds=config["time_window_seconds"],
        cooldown_seconds=config["cooldown_seconds"],
    )

    user_enum = SSHUserEnumerationDetector(
        threshold=3,
        time_window_seconds=120,
        cooldown_seconds=300,
    )

    for event in parse_log_file(log_path):
        for detector in (brute_force, user_enum):
            alert = detector.process_event(event)

            if alert:
                all_alerts.append(alert)
                alert = enrich_alert_with_mitre(alert)

                print(f"[ALERT] {alert['alert_type']} detected")
                print(f"  Source IP: {alert['ip']}")

                if "mitre" in alert:
                    mitre = alert["mitre"]
                    print("  MITRE ATT&CK:")
                    print(f"    Tactic: {mitre['tactic']}")
                    print(f"    Technique: {mitre['technique_id']} - {mitre['technique_name']}")
                    print(f"    Reference: {mitre['url']}")

                    print("-" * 50)
    with open("alerts.json", "w") as f:
        json.dump(all_alerts, f, default=str, indent=4)

    print(f"\n[INFO] {len(all_alerts)} alerts saved to alerts.json")
