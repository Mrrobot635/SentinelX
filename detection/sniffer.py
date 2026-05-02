"""
SentinelX - Network Sniffer Module
Captures TCP/SYN packets to detect port scanning.

Monitors the enp0s8 interface (Host-Only network only).
This was a deliberate choice made after testing showed
that monitoring all interfaces flooded the engine with
irrelevant NAT traffic from the browser and OS.
Restricting to enp0s8 ensures only internal threats
are detected.
"""

import os
import sys
import threading
import logging

sys.path.insert(0, os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))))

from database.manager import DatabaseManager
from detection.engine import DetectionEngine

logger = logging.getLogger('SentinelX.Sniffer')

# IPs to ignore
WHITELIST = ['127.0.0.1', '0.0.0.0']

# Network interface to monitor
# enp0s8 = Host-Only interface (internal network)
# Change to None to monitor all interfaces
MONITOR_INTERFACE = "enp0s8"


class NetworkSniffer:
    """
    Monitors the internal network interface (enp0s8).
    I chose this interface specifically because
    monitoring all interfaces captured too much
    irrelevant NAT traffic and caused false positives.
    This way we only see internal network activity.
    Captures network packets and detects port scanning.
    
    """

    def __init__(self):
        self.db      = DatabaseManager()
        self.engine  = DetectionEngine(self.db)
        self.running = False
        self.thread  = None

    def start(self):
        """Start sniffing in a background thread"""
        self.running = True
        self.thread  = threading.Thread(
            target=self._sniff,
            daemon=True
        )
        self.thread.start()
        print("[SNIFFER] Network sniffer started")
        if MONITOR_INTERFACE:
            print(f"[SNIFFER] Monitoring interface: {MONITOR_INTERFACE}")
        else:
            print("[SNIFFER] Monitoring all interfaces")
        print("[SNIFFER] Watching for port scan activity...")
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
        Listens on enp0s8 (Host-Only) to monitor internal
        network traffic only — ignores internet NAT traffic.
        """
        try:
            from scapy.all import sniff, IP, TCP

            kwargs = {
                "filter": "tcp[tcpflags] & tcp-syn != 0",
                "prn": self._packet_callback,
                "store": 0,
                "stop_filter": lambda x: not self.running
            }

            # Specify interface if defined
            if MONITOR_INTERFACE:
                kwargs["iface"] = MONITOR_INTERFACE

            sniff(**kwargs)

        except PermissionError:
            print("[SNIFFER] Permission denied.")
            print("[SNIFFER] Run with: sudo venv/bin/python3 main.py")
        except OSError as e:
            if "No such device" in str(e):
                print(f"[SNIFFER] Interface '{MONITOR_INTERFACE}' not found.")
                print("[SNIFFER] Falling back to all interfaces...")
                self._sniff_all_interfaces()
            else:
                print(f"[SNIFFER] Error: {e}")
                logger.error(f"Sniffer error: {e}")
        except Exception as e:
            print(f"[SNIFFER] Error: {e}")
            logger.error(f"Sniffer error: {e}")

    def _sniff_all_interfaces(self):
        """Fallback: sniff on all interfaces"""
        try:
            from scapy.all import sniff
            print("[SNIFFER] Sniffing on all interfaces (fallback)")
            sniff(
                filter="tcp[tcpflags] & tcp-syn != 0",
                prn=self._packet_callback,
                store=0,
                stop_filter=lambda x: not self.running
            )
        except Exception as e:
            print(f"[SNIFFER] Fallback error: {e}")

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

            src_ip   = packet[IP].src
            dst_port = packet[TCP].dport

            # Skip whitelisted IPs
            if src_ip in WHITELIST:
                return

            # Skip our own honeypot and dashboard ports
            if dst_port in [2222, 5000]:
                return

            print(f"[SNIFFER] Packet: {src_ip} → port {dst_port}")

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

# STANDALONE TEST

if __name__ == '__main__':
    import time
    print("[SNIFFER] Starting standalone test...")
    print(f"[SNIFFER] Interface: {MONITOR_INTERFACE or 'all'}")
    print("[SNIFFER] NOTE: Requires root/sudo privileges")

    sniffer = NetworkSniffer()
    sniffer.start()

    print("[SNIFFER] Sniffing for 60 seconds...")
    print("[SNIFFER] Run nmap from Kali to test:")
    print("[SNIFFER] nmap -sS 192.168.56.102")

    try:
        time.sleep(60)
    except KeyboardInterrupt:
        pass
    finally:
        sniffer.stop()