import yaml

def load_config(path="config.yaml"):
    """
    Load IDS configuration from YAML file.
    """
    try:
        with open(path, "r") as f:
            config = yaml.safe_load(f)
    except FileNotFoundError:
        raise RuntimeError(f"Config file not found: {path}")

    # Basic validation
    try:
        ssh_config = config["ssh"]["brute_force"]
        return {
            "threshold": int(ssh_config["threshold"]),
            "time_window_seconds": int(ssh_config["time_window_seconds"]),
            "cooldown_seconds": int(ssh_config["cooldown_seconds"]),
        }
    except (KeyError, TypeError, ValueError):
        raise RuntimeError("Invalid or missing SSH brute-force configuration")
