from parser import parse_log_file
from rules import SSHBruteForceDetector, SSHUserEnumerationDetector
from config import load_config
from mitre import enrich_alert_with_mitre

if __name__ == "__main__":
    config = load_config()

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

    for event in parse_log_file("samples/auth.log"):
        for detector in (brute_force, user_enum):
            alert = detector.process_event(event)
            if alert:
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
