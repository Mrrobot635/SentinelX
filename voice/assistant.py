"""
SentinelX - Voice Assistant Module
100% local - no external API
Uses pyttsx3 + SpeechRecognition

Features:
- Wake word "Sentinel" activates listening
- Voice commands processed locally
- Automatic alert announcements
- Voice-controlled IP blocking
"""

import pyttsx3
import speech_recognition as sr
import threading
import time
import sys
import os

sys.path.insert(0, os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))))

from database.manager import DatabaseManager

# Global TTS lock
_tts_lock = threading.Lock()


def _speak_worker(text):
    """Standalone TTS worker — fresh engine each call"""
    with _tts_lock:
        try:
            engine = pyttsx3.init()
            engine.setProperty('rate', 150)
            engine.setProperty('volume', 1.0)
            engine.say(text)
            engine.runAndWait()
            engine.stop()
        except Exception as e:
            print(f"[VOICE] TTS error: {e}")


class VoiceAssistant:
    """
    Local voice assistant for SentinelX.
    Wake word: 'Sentinel'
    All processing done locally — no external API.
    """

    def __init__(self):
        self.db            = DatabaseManager()
        self.enabled       = False
        self.wake_active   = False  # True when listening for commands
        self.wake_thread   = None
        self.recognizer    = sr.Recognizer()
        self.recognizer.energy_threshold = 3000
        self.recognizer.pause_threshold  = 0.8
        print("[VOICE] Voice assistant initialized")
        print("[VOICE] Wake word: 'Sentinel'")

    # ─────────────────────────────────────────
    # SPEAK
    # ─────────────────────────────────────────

    def speak(self, text):
        """Speak synchronously"""
        print(f"[VOICE] Speaking: {text}")
        _speak_worker(text)

    def speak_async(self, text):
        """Speak in background thread"""
        print(f"[VOICE] Queuing: {text}")
        thread = threading.Thread(
            target=_speak_worker,
            args=(text,)
        )
        thread.daemon = False
        thread.start()
        return thread

    # ─────────────────────────────────────────
    # WAKE WORD LOOP
    # ─────────────────────────────────────────

    def start_wake_word_loop(self):
        """
        Continuously listens for wake word 'Sentinel'.
        When heard → listens for command → processes it.
        Runs in background thread.
        """
        self.wake_active = True
        print("[VOICE] Wake word loop started")
        print("[VOICE] Say 'Sentinel' to activate")

        while self.wake_active and self.enabled:
            try:
                # Listen for wake word
                text = self._listen_once(timeout=3)

                if text and 'sentinel' in text.lower():
                    print("[VOICE] Wake word detected!")
                    self.speak("Yes, I am listening.")

                    # Listen for actual command
                    time.sleep(0.3)
                    command = self._listen_once(timeout=6)

                    if command:
                        self.process_command(command)
                    else:
                        self.speak_async(
                            "I did not hear a command. "
                            "Say Sentinel to try again."
                        )

            except Exception as e:
                print(f"[VOICE] Wake loop error: {e}")
                time.sleep(1)

        print("[VOICE] Wake word loop stopped")

    def stop_wake_word_loop(self):
        """Stop the wake word loop"""
        self.wake_active = False
        print("[VOICE] Wake word loop stopping...")

    def _listen_once(self, timeout=3):
        """
        Listen for speech once and return text.
        Returns None if nothing heard or error.
        """
        try:
            with sr.Microphone() as source:
                self.recognizer.adjust_for_ambient_noise(
                    source, duration=0.3)
                audio = self.recognizer.listen(
                    source,
                    timeout=timeout,
                    phrase_time_limit=8
                )
            text = self.recognizer.recognize_google(audio)
            print(f"[VOICE] Heard: {text}")
            return text.lower()

        except sr.WaitTimeoutError:
            return None  # Normal — no one spoke
        except sr.UnknownValueError:
            return None  # Could not understand
        except sr.RequestError as e:
            print(f"[VOICE] Recognition error: {e}")
            return None
        except Exception as e:
            print(f"[VOICE] Listen error: {e}")
            return None

    # ─────────────────────────────────────────
    # ALERT ANNOUNCEMENT
    # ─────────────────────────────────────────

    def announce_alert(self, alert_data):
        """Announce security alert vocally"""
        if not self.enabled:
            return

        severity    = alert_data.get('severity', 'Unknown')
        attack_type = alert_data.get('attack_type', 'Unknown')
        ip          = alert_data.get('ip_address', 'Unknown')
        details     = alert_data.get('details', '')

        if attack_type == 'BRUTE_FORCE':
            attack_label = 'brute force S.S.H attack'
        elif attack_type == 'PORT_SCAN':
            attack_label = 'port scan'
        else:
            attack_label = attack_type

        # Extract attempt count from details if available
        count_info = ''
        if 'SSH login attempts' in details:
            try:
                count = details.split(' ')[0]
                count_info = f"{count} login attempts recorded. "
            except Exception:
                pass

        # Urgent prefix for critical/high
        prefix = ''
        if severity == 'Critical':
            prefix = 'URGENT. '
        elif severity == 'High':
            prefix = 'Warning. '

        message = (
            f"{prefix}"
            f"Security alert. "
            f"{severity} severity. "
            f"{attack_label} detected "
            f"from IP {ip}. "
            f"{count_info}"
            f"Please check the dashboard."
        )

        self.speak_async(message)

    # ─────────────────────────────────────────
    # COMMAND PROCESSING
    # ─────────────────────────────────────────

    def process_command(self, command):
        """
        Process voice or typed command locally.
        Keyword matching — no external AI.
        """
        if not command:
            response = "No command received."
            self.speak_async(response)
            return response

        command = command.lower().strip()
        print(f"[VOICE] Processing: {command}")

        # ── BLOCK IP ──
        if any(w in command for w in [
            'block', 'ban', 'stop this ip',
            'block this ip', 'block ip'
        ]):
            response = self._handle_block_command(command)

        # ── UNBLOCK ──
        elif any(w in command for w in [
            'unblock', 'allow', 'release'
        ]):
            response = self._handle_unblock_command()

        # ── HOW MANY ATTACKS ──
        elif any(w in command for w in [
            'how many', 'attacks today', 'alerts today',
            'total', 'count', 'attacks', 'how much'
        ]):
            response = self._report_today()

        # ── STATUS ──
        elif any(w in command for w in [
            'status', 'system status', 'overview', 'running'
        ]):
            response = self._report_status()

        # ── TOP ATTACKER ──
        elif any(w in command for w in [
            'top attacker', 'worst', 'most active',
            'top ip', 'who attacked'
        ]):
            response = self._report_top_attacker()

        # ── CRITICAL ──
        elif any(w in command for w in [
            'critical', 'high severity',
            'dangerous', 'urgent'
        ]):
            response = self._report_critical()

        # ── BRUTE FORCE ──
        elif any(w in command for w in [
            'brute force', 'ssh', 'password', 'brute'
        ]):
            response = self._report_brute_force()

        # ── PORT SCAN ──
        elif any(w in command for w in [
            'port scan', 'scanning', 'scan'
        ]):
            response = self._report_port_scan()

        # ── BLOCKED LIST ──
        elif any(w in command for w in [
            'blocked', 'block list', 'who is blocked'
        ]):
            response = self._report_blocked()

        # ── HELP ──
        elif any(w in command for w in [
            'help', 'commands', 'what can you do'
        ]):
            response = self._report_help()

        # ── UNKNOWN ──
        else:
            response = (
                "Command not recognized. "
                "Say Sentinel then try: "
                "how many attacks, "
                "system status, "
                "block this IP, "
                "or top attacker."
            )

        print(f"[VOICE] Response: {response}")
        self.speak_async(response)
        return response

    # ─────────────────────────────────────────
    # BLOCK / UNBLOCK VIA VOICE
    # ─────────────────────────────────────────

    def _handle_block_command(self, command):
        """
        Handle voice block command.
        Blocks the most recent unblocked attacker IP.
        """
        try:
            # Get most recent alert IP not yet blocked
            alerts  = self.db.get_alerts(limit=10)
            blocked = self.db.get_blocked_ips()
            blocked_set = set(b['ip_address'] for b in blocked)

            target_ip = None
            for alert in alerts:
                if alert['ip_address'] not in blocked_set:
                    target_ip = alert['ip_address']
                    break

            if not target_ip:
                return (
                    "No unblocked attackers found. "
                    "All active IPs are already blocked."
                )

            # Block in database
            self.db.block_ip(
                target_ip,
                'Blocked via voice command'
            )

            # Execute firewall rule if on Linux
            import platform
            import subprocess
            if platform.system() == 'Linux':
                try:
                    subprocess.run([
                        'iptables', '-A', 'INPUT',
                        '-s', target_ip, '-j', 'DROP'
                    ], check=True, capture_output=True)
                except Exception:
                    pass

            # Notify dashboard via Socket.io
            try:
                from dashboard.app import socketio
                socketio.emit('ip_blocked', {
                    'ip_address': target_ip,
                    'reason': 'Blocked via voice command',
                    'method': 'voice'
                })
            except Exception:
                pass

            return (
                f"IP address {target_ip} has been blocked. "
                f"All connections from this address "
                f"are now denied."
            )

        except Exception as e:
            return f"Could not block IP. Error: {e}"

    def _handle_unblock_command(self):
        """Unblock the most recently blocked IP"""
        try:
            blocked = self.db.get_blocked_ips()
            if not blocked:
                return "No IP addresses are currently blocked."

            # Unblock most recent
            target_ip = blocked[0]['ip_address']
            self.db.unblock_ip(target_ip)

            return (
                f"IP address {target_ip} has been unblocked. "
                f"Connections from this address are now allowed."
            )
        except Exception as e:
            return f"Could not unblock IP. Error: {e}"

    # ─────────────────────────────────────────
    # REPORTS
    # ─────────────────────────────────────────

    def _report_today(self):
        try:
            stats    = self.db.get_alert_statistics()
            total    = stats.get('total', 0)
            critical = stats.get(
                'by_severity', {}).get('Critical', 0)
            high     = stats.get(
                'by_severity', {}).get('High', 0)
            medium   = stats.get(
                'by_severity', {}).get('Medium', 0)
            low      = stats.get(
                'by_severity', {}).get('Low', 0)
            brute    = stats.get(
                'by_type', {}).get('BRUTE_FORCE', 0)
            scan     = stats.get(
                'by_type', {}).get('PORT_SCAN', 0)

            if total == 0:
                return (
                    "No security alerts detected yet. "
                    "The network appears clean."
                )
            return (
                f"SentinelX has recorded {total} security "
                f"alert{'s' if total != 1 else ''}. "
                f"{critical} critical, "
                f"{high} high, "
                f"{medium} medium, "
                f"and {low} low severity. "
                f"Including {brute} brute force attack"
                f"{'s' if brute != 1 else ''} "
                f"and {scan} port scan"
                f"{'s' if scan != 1 else ''}."
            )
        except Exception as e:
            return f"Could not retrieve data. Error: {e}"

    def _report_status(self):
        try:
            stats   = self.db.get_alert_statistics()
            total   = stats.get('total', 0)
            top     = stats.get('top_ips', [])
            blocked = self.db.get_blocked_ips()
            nb      = len(blocked)

            msg = (
                f"SentinelX is active and monitoring "
                f"the Influence Mood network. "
                f"{total} total alert"
                f"{'s' if total != 1 else ''} recorded. "
                f"{nb} IP address"
                f"{'es' if nb != 1 else ''} blocked. "
            )
            if top:
                msg += (
                    f"Top attacker is IP "
                    f"{top[0]['ip_address']} "
                    f"with {top[0]['count']} alert"
                    f"{'s' if top[0]['count'] != 1 else ''}."
                )
            else:
                msg += "No active attackers detected."
            return msg
        except Exception as e:
            return f"Could not retrieve status. Error: {e}"

    def _report_top_attacker(self):
        try:
            stats = self.db.get_alert_statistics()
            top   = stats.get('top_ips', [])
            if not top:
                return "No attackers detected yet."
            return (
                f"Top attacker is IP "
                f"{top[0]['ip_address']} "
                f"with {top[0]['count']} alert"
                f"{'s' if top[0]['count'] != 1 else ''}."
            )
        except Exception as e:
            return f"Could not retrieve data. Error: {e}"

    def _report_critical(self):
        try:
            critical = self.db.get_alerts(
                severity='Critical', limit=10)
            high     = self.db.get_alerts(
                severity='High', limit=10)
            total    = len(critical) + len(high)
            if total == 0:
                return (
                    "No critical alerts. "
                    "Network is stable."
                )
            return (
                f"Warning. {total} critical and high "
                f"severity alert"
                f"{'s' if total != 1 else ''} "
                f"require immediate attention."
            )
        except Exception as e:
            return f"Could not retrieve data. Error: {e}"

    def _report_brute_force(self):
        try:
            stats = self.db.get_alert_statistics()
            count = stats.get(
                'by_type', {}).get('BRUTE_FORCE', 0)
            if count == 0:
                return "No brute force attacks detected."
            return (
                f"SentinelX detected {count} brute force "
                f"SSH attack{'s' if count != 1 else ''}. "
                f"All attempts were denied by the honeypot."
            )
        except Exception as e:
            return f"Could not retrieve data. Error: {e}"

    def _report_port_scan(self):
        try:
            stats = self.db.get_alert_statistics()
            count = stats.get(
                'by_type', {}).get('PORT_SCAN', 0)
            if count == 0:
                return "No port scan activity detected."
            return (
                f"SentinelX detected {count} port scan "
                f"attempt{'s' if count != 1 else ''}. "
                f"Possible internal reconnaissance."
            )
        except Exception as e:
            return f"Could not retrieve data. Error: {e}"

    def _report_blocked(self):
        try:
            blocked = self.db.get_blocked_ips()
            count   = len(blocked)
            if count == 0:
                return "No IP addresses currently blocked."
            ips = ', '.join(
                [b['ip_address'] for b in blocked[:3]])
            return (
                f"{count} IP address"
                f"{'es' if count != 1 else ''} blocked: "
                f"{ips}."
            )
        except Exception as e:
            return f"Could not retrieve data. Error: {e}"

    def _report_help(self):
        return (
            "Say Sentinel to wake me up, then ask: "
            "how many attacks. "
            "System status. "
            "Top attacker. "
            "Critical alerts. "
            "Block this IP. "
            "Or: who is blocked."
        )

    # ─────────────────────────────────────────
    # ENABLE / DISABLE
    # ─────────────────────────────────────────

    def enable(self):
        """Enable voice assistant and start wake word loop"""
        self.enabled = True
        print("[VOICE] Enabled")

        # Announce activation
        self.speak_async(
            "SentinelX voice assistant activated. "
            "Say Sentinel to give a command."
        )

        # Start wake word loop in background
        if self.wake_thread is None or \
                not self.wake_thread.is_alive():
            self.wake_thread = threading.Thread(
                target=self.start_wake_word_loop,
                daemon=True
            )
            self.wake_thread.start()
            print("[VOICE] Wake word thread started")

    def disable(self):
        """Disable voice assistant"""
        self.enabled = False
        self.stop_wake_word_loop()
        print("[VOICE] Disabled")


# ─────────────────────────────────────────
# STANDALONE TEST
# ─────────────────────────────────────────
if __name__ == '__main__':
    print("[VOICE] Standalone test starting...")
    assistant = VoiceAssistant()
    assistant.enabled = True

    # Test 1 — Basic speech
    print("\n[TEST 1] Basic speech")
    assistant.speak(
        "SentinelX online. All systems operational."
    )
    time.sleep(2)

    # Test 2 — Alert announcement
    print("\n[TEST 2] Alert announcement")
    t = assistant.speak_async(
        "Security alert. High severity. "
        "Brute force S.S.H attack detected "
        "from IP 192.168.1.45. "
        "Please check the dashboard."
    )
    t.join()
    time.sleep(1)

    # Test 3 — Voice command
    print("\n[TEST 3] Command: how many attacks")
    response = assistant.process_command(
        "how many attacks today")
    print(f"Response: {response}")
    time.sleep(8)

    # Test 4 — Block command
    print("\n[TEST 4] Command: block this IP")
    response = assistant.process_command("block this ip")
    print(f"Response: {response}")
    time.sleep(6)

    # Test 5 — Wake word loop
    print("\n[TEST 5] Wake word loop")
    print("Say 'Sentinel' then ask a question...")
    print("Press Ctrl+C to stop")
    try:
        assistant.start_wake_word_loop()
    except KeyboardInterrupt:
        assistant.stop_wake_word_loop()
        print("\n[VOICE] Test complete")