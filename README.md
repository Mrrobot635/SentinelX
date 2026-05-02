# SentinelX — Network Security Monitoring System

SentinelX is a lightweight network security monitoring platform
developed for Influence Mood Digital Agency in Abidjan, Cote d'Ivoire.
It was built as part of an NCC Education Level 5 Computing Project.

The system combines four modules that run simultaneously:
an SSH honeypot that captures intrusion attempts, a network sniffer
that detects port scanning, a detection engine that classifies threats,
and a real-time web dashboard for the administrator.

## What it does

- Listens for SSH login attempts on port 2222 and logs every
  username and password tried, without ever granting access
- Monitors internal network traffic for port scanning activity
- Generates alerts classified as Low, Medium, High or Critical
- Displays everything in a browser-accessible dashboard
- Allows the administrator to block a suspicious IP with one click
- Includes an optional voice assistant that announces alerts
  and responds to spoken commands, with no cloud dependency

## Requirements

- Python 3.12 or higher
- Ubuntu 24.04 LTS recommended for deployment
- VirtualBox for the lab environment
- Chrome , Edge or Firefox browser for the dashboard

## Installation

```bash
git clone https://github.com/Mrrobot635/SentinelX.git
cd SentinelX
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

On Ubuntu, also install the system dependency for audio:

```bash
sudo apt install -y espeak portaudio19-dev
```

## Running the system

```bash
# Requires sudo on Linux for the network sniffer (Scapy)
sudo venv/bin/python3 main.py
```

Then open your browser and go to http://localhost:5000

## Project structure

SentinelX/
├── main.py                  # Entry point, launches all modules
├── requirements.txt
├── honeypot/
│   └── ssh_honeypot.py      # SSH honeypot on port 2222
├── detection/
│   ├── engine.py            # Brute force and port scan detection
│   └── sniffer.py           # Network packet capture (Scapy)
├── dashboard/
│   ├── app.py               # Flask backend and Socket.io
│   ├── templates/
│   │   └── index.html       # Dashboard UI
│   └── static/
│       ├── style.css
│       └── dashboard.js
├── database/
│   └── manager.py           # SQLite database handler
├── voice/
│   └── assistant.py         # Local voice assistant
└── tests/
├── test_honeypot.py
├── test_detection.py
└── test_dashboard.py

## Voice assistant

Say the wake word **Sentinel** to activate listening, then ask:

- "how many attacks today"
- "system status"
- "top attacker"
- "critical alerts"
- "block this IP"
- "who is blocked"

## Notes

- IP blocking via iptables works on Linux only. On Windows,
  blocks are recorded in the database but no firewall rule is applied.
- iptables rules do not persist after a system reboot.
  This is a known limitation documented in the project report.
- The voice assistant requires a microphone and Chrome browser.

## Developed by

Yao Kanvoumien Paul Elie
NCC Education Level 5 Diploma in Computing
AVIDE Education — 2026