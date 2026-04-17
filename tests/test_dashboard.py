"""
SentinelX - Unit Tests : Dashboard API
Tests Flask API endpoints.
"""

import sys
import os
import unittest
import json

sys.path.insert(0, os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))))

from database.manager import DatabaseManager


class TestDashboardAPI(unittest.TestCase):
    """Unit tests for Dashboard API endpoints"""

    def setUp(self):
        """Set up Flask test client"""
        from dashboard.app import app
        app.config['TESTING'] = True
        self.client = app.test_client()
        self.db = DatabaseManager()

        # Insert test data
        conn = self.db.get_connection()
        conn.execute('DELETE FROM alerts')
        conn.execute('DELETE FROM ssh_events')
        conn.execute('DELETE FROM blocked_ips')
        conn.commit()
        conn.close()

        # Add sample alert
        self.db.insert_alert(
            ip_address='192.168.56.101',
            attack_type='BRUTE_FORCE',
            severity='High',
            details='Test alert'
        )

        # Add sample SSH event
        self.db.insert_ssh_event(
            ip_address='192.168.56.101',
            username='root',
            password='toor',
            session_id='api-test-001'
        )

    # ─────────────────────────────────────────
    # TC12 — Dashboard loads
    # ─────────────────────────────────────────
    def test_TC12_dashboard_loads(self):
        """
        TC12: Verify dashboard page loads correctly
        Expected: HTTP 200 response
        """
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        print("TC12 PASS: Dashboard page loads correctly")

    # ─────────────────────────────────────────
    # TC13 — Alerts API returns data
    # ─────────────────────────────────────────
    def test_TC13_alerts_api(self):
        """
        TC13: Verify /api/alerts returns correct data
        Expected: JSON list with at least 1 alert
        """
        response = self.client.get('/api/alerts')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIsInstance(data, list)
        self.assertGreater(len(data), 0)
        self.assertEqual(data[0]['attack_type'],
                         'BRUTE_FORCE')
        print("TC13 PASS: Alerts API returns correct data")

    # ─────────────────────────────────────────
    # TC14 — Statistics API
    # ─────────────────────────────────────────
    def test_TC14_statistics_api(self):
        """
        TC14: Verify /api/statistics returns valid stats
        Expected: JSON with total, by_severity, by_type
        """
        response = self.client.get('/api/statistics')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('total', data)
        self.assertIn('by_severity', data)
        self.assertIn('by_type', data)
        self.assertIn('top_ips', data)
        self.assertGreater(data['total'], 0)
        print("TC14 PASS: Statistics API returns valid data")

    # ─────────────────────────────────────────
    # TC15 — SSH events API
    # ─────────────────────────────────────────
    def test_TC15_ssh_events_api(self):
        """
        TC15: Verify /api/ssh_events returns events
        Expected: JSON list with captured credentials
        """
        response = self.client.get('/api/ssh_events')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIsInstance(data, list)
        self.assertGreater(len(data), 0)
        self.assertIn('username', data[0])
        self.assertIn('password', data[0])
        print("TC15 PASS: SSH events API returns credentials")

    # ─────────────────────────────────────────
    # TC16 — Block IP API
    # ─────────────────────────────────────────
    def test_TC16_block_ip_api(self):
        """
        TC16: Verify /api/block_ip blocks correctly
        Expected: IP added to blocked_ips table
        """
        response = self.client.post(
            '/api/block_ip',
            data=json.dumps({
                'ip_address': '192.168.56.101',
                'reason': 'Unit test block'
            }),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data['success'])

        # Verify in DB
        blocked = self.db.get_blocked_ips()
        blocked_ips = [b['ip_address'] for b in blocked]
        self.assertIn('192.168.56.101', blocked_ips)
        print("TC16 PASS: Block IP API works correctly")

    # ─────────────────────────────────────────
    # TC17 — Unblock IP API
    # ─────────────────────────────────────────
    def test_TC17_unblock_ip_api(self):
        """
        TC17: Verify /api/unblock_ip unblocks correctly
        Expected: IP removed from blocked_ips table
        """
        # First block
        self.db.block_ip('192.168.56.200', 'Test block')

        # Then unblock
        response = self.client.post(
            '/api/unblock_ip',
            data=json.dumps({
                'ip_address': '192.168.56.200'
            }),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data['success'])

        # Verify removed from DB
        blocked = self.db.get_blocked_ips()
        blocked_ips = [b['ip_address'] for b in blocked]
        self.assertNotIn('192.168.56.200', blocked_ips)
        print("TC17 PASS: Unblock IP API works correctly")

    # ─────────────────────────────────────────
    # TC18 — Filter alerts by severity
    # ─────────────────────────────────────────
    def test_TC18_filter_alerts_by_severity(self):
        """
        TC18: Verify alerts can be filtered by severity
        Expected: Only High alerts returned
        """
        response = self.client.get('/api/alerts/High')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        for alert in data:
            self.assertEqual(alert['severity'], 'High')
        print("TC18 PASS: Alert filtering works correctly")

    # ─────────────────────────────────────────
    # TC19 — Export CSV
    # ─────────────────────────────────────────
    def test_TC19_export_csv(self):
        """
        TC19: Verify CSV export works correctly
        Expected: CSV file returned with correct headers
        """
        response = self.client.get('/api/export/csv')
        self.assertEqual(response.status_code, 200)
        self.assertIn(
            b'ip_address',
            response.data
        )
        print("TC19 PASS: CSV export works correctly")


if __name__ == '__main__':
    print("=" * 55)
    print("SentinelX — Unit Tests : Dashboard API")
    print("=" * 55)
    unittest.main(verbosity=2)