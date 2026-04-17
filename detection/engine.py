"""
SentinelX - Detection Engine
Analyses events from honeypot and sniffer.
Detects brute force SSH and port scanning attacks.
Classifies alerts by severity level.

Context: Developed for Influence Mood digital agency
to monitor internal network threats.
"""

import os
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))))

from database.manager import DatabaseManager

# ─────────────────────────────────────────
# DETECTION THRESHOLDS
# ─────────────────────────────────────────

BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW    = 60   # seconds

PORT_SCAN_THRESHOLD   = 10
PORT_SCAN_WINDOW      = 30   # seconds


class DetectionEngine:
    """
    Core detection engine for SentinelX.
    Analyses stored events and generates alerts
    when attack thresholds are exceeded.
    """

    def __init__(self, db_manager=None):
        self.db = db_manager if db_manager else DatabaseManager()
        self.recent_alerts = {}

    # ─────────────────────────────────────────
    # HUMAN READABLE TIME
    # ─────────────────────────────────────────

    def _seconds_to_label(self, seconds):
        """Convert seconds to human readable string"""
        if seconds < 60:
            return f"{seconds} seconds"
        elif seconds < 3600:
            minutes = seconds // 60
            return f"{minutes} minute{'s' if minutes > 1 else ''}"
        else:
            hours = seconds // 3600
            return f"{hours} hour{'s' if hours > 1 else ''}"

    # ─────────────────────────────────────────
    # BRUTE FORCE DETECTION
    # ─────────────────────────────────────────

    def check_brute_force(self, ip_address):
        """
        Check if an IP has exceeded the brute force threshold.
        Triggered after every SSH attempt from that IP.
        """
        conn = self.db.get_connection()
        cursor = conn.cursor()

        window_start = datetime.now() - timedelta(
            seconds=BRUTE_FORCE_WINDOW)

        cursor.execute('''
            SELECT COUNT(*) as attempt_count
            FROM ssh_events
            WHERE ip_address = ?
            AND timestamp >= ?
        ''', (ip_address,
              window_start.strftime('%Y-%m-%d %H:%M:%S')))

        result = cursor.fetchone()
        attempt_count = result['attempt_count']
        conn.close()

        print(f"[ENGINE] Brute force check: {ip_address} "
              f"→ {attempt_count} attempts "
              f"in last {self._seconds_to_label(BRUTE_FORCE_WINDOW)}")

        if attempt_count >= BRUTE_FORCE_THRESHOLD:
            if not self._is_duplicate_alert(
                    ip_address, 'BRUTE_FORCE'):
                severity = self._classify_brute_force(attempt_count)
                window_label = self._seconds_to_label(
                    BRUTE_FORCE_WINDOW)
                details = (
                    f"{attempt_count} SSH login attempts detected "
                    f"from this IP within {window_label}"
                )
                alert_id = self.db.insert_alert(
                    ip_address=ip_address,
                    attack_type='BRUTE_FORCE',
                    severity=severity,
                    details=details
                )
                self._emit_alert(
                    alert_id, ip_address,
                    'BRUTE_FORCE', severity, details)
                return True
        return False

    def _classify_brute_force(self, attempt_count):
        """
        Classify brute force severity.
        Low      :  5-9 attempts
        Medium   : 10-19 attempts
        High     : 20-49 attempts
        Critical : 50+ attempts
        """
        if attempt_count >= 50:
            return 'Critical'
        elif attempt_count >= 20:
            return 'High'
        elif attempt_count >= 10:
            return 'Medium'
        else:
            return 'Low'

    # ─────────────────────────────────────────
    # PORT SCAN DETECTION
    # ─────────────────────────────────────────

    def check_port_scan(self, ip_address):
        """
        Check if an IP is performing a port scan.
        Triggered after every packet captured by the sniffer.
        """
        conn = self.db.get_connection()
        cursor = conn.cursor()

        window_start = datetime.now() - timedelta(
            seconds=PORT_SCAN_WINDOW)

        cursor.execute('''
            SELECT COUNT(DISTINCT port_number) as unique_ports
            FROM port_scan_events
            WHERE ip_address = ?
            AND timestamp >= ?
        ''', (ip_address,
              window_start.strftime('%Y-%m-%d %H:%M:%S')))

        result = cursor.fetchone()
        unique_ports = result['unique_ports']
        conn.close()

        print(f"[ENGINE] Port scan check: {ip_address} "
              f"→ {unique_ports} unique ports "
              f"in last {self._seconds_to_label(PORT_SCAN_WINDOW)}")

        if unique_ports >= PORT_SCAN_THRESHOLD:
            if not self._is_duplicate_alert(
                    ip_address, 'PORT_SCAN'):
                severity = self._classify_port_scan(unique_ports)
                window_label = self._seconds_to_label(
                    PORT_SCAN_WINDOW)
                details = (
                    f"{unique_ports} unique ports scanned "
                    f"from this IP within {window_label}"
                )
                alert_id = self.db.insert_alert(
                    ip_address=ip_address,
                    attack_type='PORT_SCAN',
                    severity=severity,
                    details=details
                )
                self._emit_alert(
                    alert_id, ip_address,
                    'PORT_SCAN', severity, details)
                return True
        return False

    def _classify_port_scan(self, unique_ports):
        """
        Classify port scan severity.
        Low      :  10-24 ports
        Medium   :  25-99 ports
        High     : 100-499 ports
        Critical : 500+ ports
        """
        if unique_ports >= 500:
            return 'Critical'
        elif unique_ports >= 100:
            return 'High'
        elif unique_ports >= 25:
            return 'Medium'
        else:
            return 'Low'

    # ─────────────────────────────────────────
    # DUPLICATE PREVENTION
    # ─────────────────────────────────────────

    def _is_duplicate_alert(self, ip_address, attack_type):
        """
        Prevent alert flooding.
        Same IP + same type → max 1 alert per 60 seconds.
        """
        key = f"{ip_address}_{attack_type}"
        now = datetime.now()

        if key in self.recent_alerts:
            last = self.recent_alerts[key]
            if (now - last).seconds < 60:
                print(f"[ENGINE] Duplicate suppressed: {key}")
                return True

        self.recent_alerts[key] = now
        return False

    # ─────────────────────────────────────────
    # ALERT EMISSION
    # ─────────────────────────────────────────

    def _emit_alert(self, alert_id, ip_address,
                    attack_type, severity, details):
        """Push alert to dashboard via Socket.io"""
        print(f"[ENGINE] ALERT #{alert_id} | "
              f"{severity} | {attack_type} | {ip_address}")
        try:
            from dashboard.app import socketio
            socketio.emit('new_alert', {
                'id':          alert_id,
                'ip_address':  ip_address,
                'attack_type': attack_type,
                'severity':    severity,
                'details':     details,
                'timestamp':   datetime.now().strftime(
                    '%Y-%m-%d %H:%M:%S')
            })
        except Exception:
            pass


# ─────────────────────────────────────────
# STANDALONE TEST
# ─────────────────────────────────────────
if __name__ == '__main__':
    print("[ENGINE] Testing Detection Engine...")
    db     = DatabaseManager()
    engine = DetectionEngine(db)

    print("\n[TEST] Brute force check for 127.0.0.1")
    engine.check_brute_force('127.0.0.1')

    alerts = db.get_alerts()
    print(f"\n[TEST] Total alerts in DB: {len(alerts)}")
    for alert in alerts:
        print(f"  {alert}")