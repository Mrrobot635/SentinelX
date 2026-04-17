"""
SentinelX - Network Sniffer Module
Captures TCP/SYN packets to detect port scanning activity.
Uses Scapy for packet analysis.

Context: Designed for internal threat detection scenarios
where an attacker is already present on the local network
(compromised machine, rogue WiFi connection, malware, etc.)
"""

import os
import sys
import threading
import logging

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.manager import DatabaseManager
from detection.engine import DetectionEngine

logger = logging.getLogger('SentinelX.Sniffer')

# IPs to ignore (our own system)
WHITELIST = ['127.0.0.1', '0.0.0.0']


class NetworkSniffer:
    """
    Captures network packets and detects port scanning.
    
    Internal Threat Context:
    ─────────────────────────────────────────────────
    This sniffer is designed to detect reconnaissance
    activity from threats already inside the network :
    
    - Compromised machines running automated scanners
    - Rogue devices connected to internal WiFi
    - Malware performing lateral movement
    - Insider threats mapping the internal network
    - Phishing victims with RAT (Remote Access Trojan)
    
    Detection method:
    Monitors SYN packets (TCP connection initiation).
    If one IP sends SYN to 10+ different ports in 30s
    → Port scan detected → Alert generated
    ─────────────────────────────────────────────────
    """

    def __init__(self):
        self.db = DatabaseManager()
        self.engine = DetectionEngine(self.db)
        self.running = False
        self.thread = None

    def start(self):
        """Start sniffing in a background thread"""
        self.running = True
        self.thread = threading.Thread(
            target=self._sniff,
            daemon=True
        )
        self.thread.start()
        print("[SNIFFER]  Network sniffer started")
        print("[SNIFFER] Monitoring for port scan activity...")
        logger.info("Network sniffer started")

    def stop(self):
        """Stop the sniffer"""
        self.running = False
        print("[SNIFFER] Sniffer stopped")
        logger.info("Network sniffer stopped")

    def _sniff(self):
        """
        Main sniffing loop.
        Captures only TCP SYN packets (connection attempts).
        SYN flag = 0x02
        """
        try:
            from scapy.all import sniff, IP, TCP
            sniff(
                filter="tcp[tcpflags] & tcp-syn != 0",
                prn=self._packet_callback,
                store=0,
                stop_filter=lambda x: not self.running
            )
        except PermissionError:
            print("[SNIFFER]  Permission denied.")
            print("[SNIFFER] Run with administrator privileges.")
            print("[SNIFFER] On Windows: Run CMD as Administrator")
        except Exception as e:
            print(f"[SNIFFER] Error: {e}")
            logger.error(f"Sniffer error: {e}")

    def _packet_callback(self, packet):
        """
        Called for every captured SYN packet.
        Extracts source IP and destination port.
        Logs to DB and triggers port scan detection.
        """
        try:
            from scapy.all import IP, TCP

            if IP not in packet or TCP not in packet:
                return

            src_ip = packet[IP].src
            dst_port = packet[TCP].dport

            # Skip whitelisted IPs
            if src_ip in WHITELIST:
                return

            # Skip our own honeypot port
            if dst_port == 2222:
                return

            print(f"[SNIFFER]  Packet: {src_ip} → port {dst_port}")

            # Log to database
            self.db.insert_port_scan_event(
                ip_address=src_ip,
                port_number=dst_port,
                packet_type='SYN'
            )

            # Check if this IP is port scanning
            self.engine.check_port_scan(src_ip)

        except Exception as e:
            logger.debug(f"Packet processing error: {e}")


# ─────────────────────────────────────────
# STANDALONE TEST
# ─────────────────────────────────────────
if __name__ == '__main__':
    import time
    print("[SNIFFER] Starting standalone test...")
    print("[SNIFFER] NOTE: Requires Administrator privileges on Windows")
    print("[SNIFFER] Open CMD as Administrator to test")

    sniffer = NetworkSniffer()
    sniffer.start()

    print("[SNIFFER] Sniffing for 30 seconds...")
    print("[SNIFFER] Run nmap against this machine to test")

    try:
        time.sleep(30)
    except KeyboardInterrupt:
        pass
    finally:
        sniffer.stop()