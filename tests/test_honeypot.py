"""
SentinelX - Unit Tests : Honeypot Module
Tests the SSH honeypot functionality in isolation.
"""

import sys
import os
import unittest
import threading
import time

sys.path.insert(0, os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))))

from database.manager import DatabaseManager
from honeypot.ssh_honeypot import SSHHoneypot, FakeSSHServer


class TestHoneypot(unittest.TestCase):
    """Unit tests for SSH Honeypot module"""

    def setUp(self):
        """Set up test database before each test"""
        self.db = DatabaseManager()
        # Clear test data
        conn = self.db.get_connection()
        conn.execute('DELETE FROM ssh_events')
        conn.execute('DELETE FROM alerts')
        conn.commit()
        conn.close()

    # TC01 — Honeypot initialization
    
    def test_TC01_honeypot_initialization(self):
        """
        TC01: Verify honeypot initializes correctly
        Expected: SSHHoneypot object created with
                  correct host and port
        """
        honeypot = SSHHoneypot(host='0.0.0.0', port=2222)
        self.assertEqual(honeypot.host, '0.0.0.0')
        self.assertEqual(honeypot.port, 2222)
        self.assertIsNotNone(honeypot.db)
        self.assertIsNotNone(honeypot.host_key)
        print("TC01 PASS: Honeypot initialized correctly")

    # TC02 — SSH event logging

    def test_TC02_ssh_event_logging(self):
        """
        TC02: Verify SSH attempt is logged to database
        Expected: Event stored with correct IP,
                  username and password
        """
        self.db.insert_ssh_event(
            ip_address='192.168.56.101',
            username='root',
            password='password123',
            session_id='test-session-001'
        )

        events = self.db.get_ssh_events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]['ip_address'],
                         '192.168.56.101')
        self.assertEqual(events[0]['username'], 'root')
        self.assertEqual(events[0]['password'], 'password123')
        print("TC02 PASS: SSH event logged correctly")

    # TC03 — Credential capture
    
    def test_TC03_credential_capture(self):
        """
        TC03: Verify multiple credentials are captured
        Expected: All attempts stored in database
        """
        credentials = [
            ('admin', 'admin123'),
            ('root', 'toor'),
            ('user', 'password'),
            ('test', '1234'),
            ('guest', 'guest')
        ]

        for i, (username, password) in \
                enumerate(credentials):
            self.db.insert_ssh_event(
                ip_address='192.168.56.101',
                username=username,
                password=password,
                session_id=f'test-session-{i:03d}'
            )

        events = self.db.get_ssh_events()
        self.assertEqual(len(events), 5)
        usernames = [e['username'] for e in events]
        self.assertIn('admin', usernames)
        self.assertIn('root', usernames)
        print("TC03 PASS: All credentials captured correctly")

    # TC04 — Timestamp recording
    
    def test_TC04_timestamp_recording(self):
        """
        TC04: Verify timestamp is recorded with each event
        Expected: Timestamp field is not empty
        """
        self.db.insert_ssh_event(
            ip_address='192.168.56.101',
            username='admin',
            password='test',
            session_id='test-ts-001'
        )

        events = self.db.get_ssh_events()
        self.assertEqual(len(events), 1)
        self.assertIsNotNone(events[0]['timestamp'])
        self.assertNotEqual(events[0]['timestamp'], '')
        print("TC04 PASS: Timestamp recorded correctly")

    # TC05 — Duplicate session handling
   
    def test_TC05_duplicate_session(self):
        """
        TC05: Verify duplicate session IDs are handled
        Expected: Second insert with same session_id
                  is silently ignored
        """
        self.db.insert_ssh_event(
            ip_address='192.168.56.101',
            username='admin',
            password='pass1',
            session_id='duplicate-session'
        )
        self.db.insert_ssh_event(
            ip_address='192.168.56.101',
            username='admin',
            password='pass2',
            session_id='duplicate-session'
        )

        events = self.db.get_ssh_events()
        self.assertEqual(len(events), 1)
        print("TC05 PASS: Duplicate sessions handled correctly")


if __name__ == '__main__':
    print("=" * 55)
    print("SentinelX — Unit Tests : Honeypot Module")
    print("=" * 55)
    unittest.main(verbosity=2)