"""
SentinelX - SSH Honeypot Module
Simulates a vulnerable SSH server on port 2222
Captures all connection attempts without granting access
"""

import paramiko
import socket
import threading
import logging
import uuid
import os
import sys

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.manager import DatabaseManager

# ─────────────────────────────────────────
# LOGGING SETUP
# ─────────────────────────────────────────
logging.basicConfig(
    filename='logs/sentinelx.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('SentinelX.Honeypot')

# ─────────────────────────────────────────
# SSH SERVER KEY
# Generate once and reuse
# ─────────────────────────────────────────
HOST_KEY_PATH = 'honeypot/server.key'

def get_host_key():
    """Load or generate RSA host key"""
    if os.path.exists(HOST_KEY_PATH):
        return paramiko.RSAKey(filename=HOST_KEY_PATH)
    else:
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(HOST_KEY_PATH)
        print("[HONEYPOT] New RSA host key generated")
        return key

# ─────────────────────────────────────────
# FAKE SSH SERVER INTERFACE
# ─────────────────────────────────────────
class FakeSSHServer(paramiko.ServerInterface):
    """
    Simulates an SSH server that accepts connections
    but always denies authentication.
    Logs every attempt to the database.
    """

    def __init__(self, client_ip, db_manager):
        self.client_ip = client_ip
        self.db = db_manager
        self.session_id = str(uuid.uuid4())
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        """Accept channel requests to seem realistic"""
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        """
        Called when attacker tries username/password.
        Always returns failure but logs the attempt first.
        """
        print(f"[HONEYPOT] Attempt from {self.client_ip} "
              f"-> {username} / {password}")
        logger.info(f"SSH attempt: {self.client_ip} | "
                   f"{username} | {password}")

        # Log to database
        self.db.insert_ssh_event(
            ip_address=self.client_ip,
            username=username,
            password=password,
            session_id=self.session_id
        )

        # Trigger detection engine check
        self._trigger_detection(username, password)

        # Reject but set event to keep connection briefly alive
        self.event.set()

        # Always deny access
        return paramiko.AUTH_FAILED

    def check_auth_none(self, username):
        """Reject attempts with no authentication"""
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        """Reject public key authentication"""
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        """Tell client only password auth is available"""
        return 'password'

    def _trigger_detection(self, username, password):
        """Notify detection engine after each attempt"""
        try:
            from detection.engine import DetectionEngine
            engine = DetectionEngine(self.db)
            engine.check_brute_force(self.client_ip)
        except Exception as e:
            logger.error(f"Detection engine error: {e}")


# ─────────────────────────────────────────
# CLIENT HANDLER
# ─────────────────────────────────────────
def handle_client(client_socket, client_ip, host_key, db):
    """
    Handle a single SSH connection in its own thread.
    Sets up the transport layer and fake SSH server.
    """
    transport = None
    try:
        # Create SSH transport layer
        transport = paramiko.Transport(client_socket)
        transport.add_server_key(host_key)
        transport.local_version = 'SSH-2.0-OpenSSH_8.9'

        # Create and start fake server
        fake_server = FakeSSHServer(client_ip, db)

        try:
            transport.start_server(server=fake_server)
        except paramiko.SSHException as e:
            logger.debug(f"SSH negotiation failed: {e}")
            return

        # Wait longer for authentication attempt
        channel = transport.accept(60)

        # Keep transport alive to receive password
        import time
        time.sleep(2)

        if channel:
            channel.close()

    except Exception as e:
        logger.debug(f"Connection from {client_ip} ended: {e}")
    finally:
        try:
            if transport:
                transport.close()
        except:
            pass
        try:
            client_socket.close()
        except:
            pass


# ─────────────────────────────────────────
# MAIN HONEYPOT CLASS
# ─────────────────────────────────────────
class SSHHoneypot:
    """
    Main honeypot class.
    Listens on port 2222 and handles incoming SSH connections.

    Note: Port 2222 is used instead of standard port 22
    to avoid requiring administrator privileges in the
    development and testing environment. In a production
    context, port 22 would be used with appropriate privileges.
    """

    def __init__(self, host='0.0.0.0', port=2222):
        self.host = host
        self.port = port
        self.db = DatabaseManager()
        self.host_key = get_host_key()
        self.running = False
        self.server_socket = None

    def start(self):
        """Start the honeypot server"""
        self.server_socket = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )
        # Allow port reuse immediately after restart
        self.server_socket.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_REUSEADDR,
            1
        )
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(10)  # Up to 10 simultaneous connections
        self.running = True

        print(f"[HONEYPOT] SSH Honeypot listening on port {self.port}")
        print(f"[HONEYPOT] Waiting for connections...")
        logger.info(f"Honeypot started on port {self.port}")

        while self.running:
            try:
                client_socket, client_addr = self.server_socket.accept()
                client_ip = client_addr[0]
                print(f"[HONEYPOT] New connection from {client_ip}")

                # Handle each connection in a separate thread
                thread = threading.Thread(
                    target=handle_client,
                    args=(client_socket, client_ip,
                          self.host_key, self.db),
                    daemon=True
                )
                thread.start()

            except OSError:
                break  # Server was stopped

    def stop(self):
        """Stop the honeypot server"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        print("[HONEYPOT] Honeypot stopped")
        logger.info("Honeypot stopped")


# ─────────────────────────────────────────
# RUN STANDALONE
# ─────────────────────────────────────────
if __name__ == '__main__':
    honeypot = SSHHoneypot()
    try:
        honeypot.start()
    except KeyboardInterrupt:
        honeypot.stop()