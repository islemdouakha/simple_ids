# Simple IDS

A simple, signature-based Intrusion Detection System (IDS) for Linux SSH logs.

It parses logs, detects suspicious activity (failed logins, brute-force attacks, invalid user enumeration), enriches alerts with MITRE ATT&CK context, and exports alerts to JSON.

## Features

- Parses Linux SSH logs for failed, successful, and invalid login attempts
- Detects brute-force attacks with time-window and cooldown logic
- Detects invalid user enumeration attempts
- Configurable via `config.yaml` for thresholds and time windows
- MITRE ATT&CK mapping for all alerts
- Exports alerts to `alerts.json` for SIEM integration
- Unit tests

## Architecture

Log File (auth.log)
│
▼
Parser (parser.py)
│
▼
Detection Rules (rules.py)
├── SSH Brute Force
└── User Enumeration
│
▼
MITRE Enrichment (mitre.py)
│
▼
Alerts (Console + JSON file)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/islemdouakha/simple_ids.git
cd simple-ids
```
2. pip install -r requirements.txt

## Configuration

The log file path is defined in `config.yaml`, allowing the IDS to be deployed
on different systems without modifying code.

Example:
```yaml
log:
  path: /var/log/auth.log
```

## Testing

Unit tests are provided for the SSH log parser and detection rules.
Tests can be run using:

```bash
python -m pytest

