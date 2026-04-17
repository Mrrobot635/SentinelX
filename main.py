"""
SentinelX - Main Entry Point
Launches all modules simultaneously:
- SSH Honeypot (port 2222)
- Network Sniffer (Scapy)
- Web Dashboard (Flask + Socket.io)

Developed for: Influence Mood Digital Agency
Context: Internal network threat detection
"""

import threading
import time
import os
import sys
import logging

# ─────────────────────────────────────────
# LOGGING SETUP
# ─────────────────────────────────────────
logging.basicConfig(
    filename='logs/sentinelx.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('SentinelX.Main')


def start_honeypot():
    """Launch SSH Honeypot in background thread"""
    try:
        from honeypot.ssh_honeypot import SSHHoneypot
        honeypot = SSHHoneypot(host='0.0.0.0', port=2222)
        honeypot.start()
    except Exception as e:
        print(f"[MAIN] Honeypot error: {e}")
        logger.error(f"Honeypot failed: {e}")


def start_sniffer():
    """Launch Network Sniffer in background thread"""
    try:
        # Small delay to let honeypot start first
        time.sleep(2)
        from detection.sniffer import NetworkSniffer
        sniffer = NetworkSniffer()
        sniffer.start()
        # Keep thread alive
        while True:
            time.sleep(1)
    except PermissionError:
        print("[MAIN] Sniffer requires Administrator privileges")
        print("[MAIN] Run CMD as Administrator for port scan detection")
        logger.warning("Sniffer failed: insufficient privileges")
    except Exception as e:
        print(f"[MAIN] Sniffer error: {e}")
        logger.error(f"Sniffer failed: {e}")


def start_dashboard():
    """Launch Flask Dashboard"""
    try:
        # Small delay to let other modules initialize
        time.sleep(1)
        from dashboard.app import app, socketio
        print("[MAIN] Dashboard starting on http://localhost:5000")
        socketio.run(
            app,
            host='0.0.0.0',
            port=5000,
            debug=False,
            allow_unsafe_werkzeug=True,
            use_reloader=False
        )
    except Exception as e:
        print(f"[MAIN] Dashboard error: {e}")
        logger.error(f"Dashboard failed: {e}")


def print_banner():
    print("""
╔══════════════════════════════════════════╗
║         S E N T I N E L X               ║
║    Network Security Monitoring System    ║
║    Developed for Influence Mood Agency   ║
╠══════════════════════════════════════════╣
║  SSH Honeypot  →  port 2222             ║
║  Net Sniffer   →  TCP/SYN packets       ║
║  Dashboard     →  http://localhost:5000  ║
╚══════════════════════════════════════════╝
    """)


if __name__ == '__main__':
    print_banner()
    print("[MAIN] Starting SentinelX...")
    logger.info("SentinelX starting")

    # ── Thread 1 : Honeypot SSH
    honeypot_thread = threading.Thread(
        target=start_honeypot,
        name='HoneypotThread',
        daemon=True
    )

    # ── Thread 2 : Network Sniffer
    sniffer_thread = threading.Thread(
        target=start_sniffer,
        name='SnifferThread',
        daemon=True
    )

    # Start background threads
    honeypot_thread.start()
    print("[MAIN] Honeypot thread started")

    sniffer_thread.start()
    print("[MAIN] Sniffer thread started")

    # ── Main thread : Dashboard (blocking)
    # Dashboard runs in main thread to handle Flask properly
    try:
        start_dashboard()
    except KeyboardInterrupt:
        print("\n[MAIN] SentinelX stopped by user")
        logger.info("SentinelX stopped")
        sys.exit(0)