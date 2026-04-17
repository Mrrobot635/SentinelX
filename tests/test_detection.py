"""
SentinelX - Unit Tests : Detection Engine
Tests brute force and port scan detection logic.
"""

import sys
import os
import unittest
import time

sys.path.insert(0, os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))))

from database.manager import DatabaseManager
from detection.engine import DetectionEngine


class TestDetectionEngine(unittest.TestCase):
    """Unit tests for Detection Engine module"""

    def setUp(self):
        """Set up fresh test database before each test"""
        self.db = DatabaseManager()
        conn = self.db.get_connection()
        conn.execute('DELETE FROM ssh_events')
        conn.execute('DELETE FROM port_scan_events')
        conn.execute('DELETE FROM alerts')
        conn.commit()
        conn.close()
        self.engine = DetectionEngine(self.db)

    # ─────────────────────────────────────────
    # TC06 — No alert below threshold
    # ─────────────────────────────────────────
    def test_TC06_no_alert_below_threshold(self):
        """
        TC06: Verify no alert generated below threshold
        Expected: 4 attempts from same IP = no alert
                  (threshold is 5)
        """
        for i in range(4):
            self.db.insert_ssh_event(
                ip_address='192.168.56.101',
                username='root',
                password=f'pass{i}',
                session_id=f'sess-{i:03d}'
            )

        result = self.engine.check_brute_force(
            '192.168.56.101')
        alerts = self.db.get_alerts()
        self.assertFalse(result)
        self.assertEqual(len(alerts), 0)
        print("TC06 PASS: No alert below threshold")

    # ─────────────────────────────────────────
    # TC07 — Brute force alert at threshold
    # ─────────────────────────────────────────
    def test_TC07_brute_force_alert_at_threshold(self):
        """
        TC07: Verify alert generated at threshold
        Expected: 5 attempts = BRUTE_FORCE alert generated
        """
        for i in range(5):
            self.db.insert_ssh_event(
                ip_address='192.168.56.101',
                username='admin',
                password=f'attempt{i}',
                session_id=f'bf-{i:03d}'
            )

        # Temporarily extend window for test
        from detection import engine as eng
        original = eng.BRUTE_FORCE_WINDOW
        eng.BRUTE_FORCE_WINDOW = 86400

        self.engine.check_brute_force('192.168.56.101')

        eng.BRUTE_FORCE_WINDOW = original

        alerts = self.db.get_alerts()
        self.assertGreater(len(alerts), 0)
        self.assertEqual(alerts[0]['attack_type'],
                         'BRUTE_FORCE')
        self.assertEqual(alerts[0]['ip_address'],
                         '192.168.56.101')
        print("TC07 PASS: Brute force alert generated")

    # ─────────────────────────────────────────
    # TC08 — Severity classification
    # ─────────────────────────────────────────
    def test_TC08_severity_classification(self):
        """
        TC08: Verify correct severity classification
        Expected:
          5-9   attempts → Low
          10-19 attempts → Medium
          20-49 attempts → High
          50+   attempts → Critical
        """
        self.assertEqual(
            self.engine._classify_brute_force(5), 'Low')
        self.assertEqual(
            self.engine._classify_brute_force(10), 'Medium')
        self.assertEqual(
            self.engine._classify_brute_force(20), 'High')
        self.assertEqual(
            self.engine._classify_brute_force(50), 'Critical')
        print("TC08 PASS: Severity classification correct")

    # ─────────────────────────────────────────
    # TC09 — Port scan detection
    # ─────────────────────────────────────────
    def test_TC09_port_scan_detection(self):
        """
        TC09: Verify port scan alert generated
        Expected: 10+ unique ports from same IP = alert
        """
        for port in range(1, 15):
            self.db.insert_port_scan_event(
                ip_address='192.168.56.101',
                port_number=port,
                packet_type='SYN'
            )

        from detection import engine as eng
        original = eng.PORT_SCAN_WINDOW
        eng.PORT_SCAN_WINDOW = 86400

        self.engine.check_port_scan('192.168.56.101')

        eng.PORT_SCAN_WINDOW = original

        alerts = self.db.get_alerts()
        port_scan_alerts = [
            a for a in alerts
            if a['attack_type'] == 'PORT_SCAN'
        ]
        self.assertGreater(len(port_scan_alerts), 0)
        print("TC09 PASS: Port scan alert generated")

    # ─────────────────────────────────────────
    # TC10 — Duplicate alert prevention
    # ─────────────────────────────────────────
    def test_TC10_duplicate_alert_prevention(self):
        """
        TC10: Verify duplicate alerts are suppressed
        Expected: Same IP + same attack type =
                  only 1 alert within 60 seconds
        """
        for i in range(10):
            self.db.insert_ssh_event(
                ip_address='192.168.56.101',
                username='root',
                password=f'dup{i}',
                session_id=f'dup-{i:03d}'
            )

        from detection import engine as eng
        original = eng.BRUTE_FORCE_WINDOW
        eng.BRUTE_FORCE_WINDOW = 86400

        # Trigger twice
        self.engine.check_brute_force('192.168.56.101')
        self.engine.check_brute_force('192.168.56.101')

        eng.BRUTE_FORCE_WINDOW = original

        alerts = self.db.get_alerts()
        brute_alerts = [
            a for a in alerts
            if a['attack_type'] == 'BRUTE_FORCE'
        ]
        self.assertEqual(len(brute_alerts), 1)
        print("TC10 PASS: Duplicate alert prevention works")

    # ─────────────────────────────────────────
    # TC11 — Port scan severity
    # ─────────────────────────────────────────
    def test_TC11_port_scan_severity(self):
        """
        TC11: Verify port scan severity classification
        Expected:
          10-24  ports → Low
          25-99  ports → Medium
          100-499 ports → High
          500+   ports → Critical
        """
        self.assertEqual(
            self.engine._classify_port_scan(10), 'Low')
        self.assertEqual(
            self.engine._classify_port_scan(25), 'Medium')
        self.assertEqual(
            self.engine._classify_port_scan(100), 'High')
        self.assertEqual(
            self.engine._classify_port_scan(500), 'Critical')
        print("TC11 PASS: Port scan severity correct")


if __name__ == '__main__':
    print("=" * 55)
    print("SentinelX — Unit Tests : Detection Engine")
    print("=" * 55)
    unittest.main(verbosity=2)