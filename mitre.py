MITRE_ATTACK_MAP = {
    "SSH_BRUTE_FORCE": {
        "tactic": "Credential Access",
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "url": "https://attack.mitre.org/techniques/T1110/"
    },
    "SSH_USER_ENUMERATION": {
        "tactic": "Credential Access",
        "technique_id": "T1110.003",
        "technique_name": "Password Spraying / Account Discovery",
        "url": "https://attack.mitre.org/techniques/T1110/003/"
    }
}


def enrich_alert_with_mitre(alert):
    """
    Add MITRE ATT&CK context to an alert if mapping exists.
    """
    mapping = MITRE_ATTACK_MAP.get(alert["alert_type"])
    if not mapping:
        return alert

    alert["mitre"] = mapping
    return alert
