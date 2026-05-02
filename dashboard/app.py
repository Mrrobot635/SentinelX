"""
SentinelX - Dashboard Web Application
Real-time security monitoring dashboard
Built with Flask and Socket.io
"""

import os
import sys
import subprocess
import platform
import threading          
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, render_template, jsonify, send_file, request
from flask_socketio import SocketIO
from database.manager import DatabaseManager
import io
import csv


# APP SETUP

app = Flask(__name__)
app.config['SECRET_KEY'] = 'sentinelx-secret-key-2024'
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    logger=False,
    engineio_logger=False,
    ping_timeout=120,     
    ping_interval=60      
)
db = DatabaseManager()

# Global voice assistant instance
voice_assistant = None

# ROUTES

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('index.html')


@app.route('/api/alerts')
def get_alerts():
    """Return all alerts as JSON"""
    alerts = db.get_alerts(limit=100)
    return jsonify(alerts)


@app.route('/api/alerts/<severity>')
def get_alerts_by_severity(severity):
    """Return alerts filtered by severity"""
    alerts = db.get_alerts(severity=severity, limit=100)
    return jsonify(alerts)


@app.route('/api/statistics')
def get_statistics():
    """Return dashboard statistics"""
    stats = db.get_alert_statistics()
    return jsonify(stats)


@app.route('/api/ssh_events')
def get_ssh_events():
    """Return recent SSH honeypot events"""
    events = db.get_ssh_events(limit=50)
    return jsonify(events)


@app.route('/api/export/csv')
def export_csv():
    """Export alerts to CSV and download"""
    alerts = db.get_alerts(limit=10000)
    if not alerts:
        return jsonify({'error': 'No alerts to export'}), 404

    # Create CSV in memory
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=alerts[0].keys())
    writer.writeheader()
    writer.writerows(alerts)

    # Send as downloadable file
    output.seek(0)
    return app.response_class(
        output.getvalue(),
        mimetype='text/csv',
        headers={
            'Content-Disposition': 'attachment; filename=sentinelx_alerts.csv'
        }
    )

# BLOCK IP ROUTES

@app.route('/api/block_ip', methods=['POST'])
def block_ip():
    """
    Block an IP address.
    On Linux/Ubuntu : uses iptables
    On Windows (dev): logs the block only (simulation)
    """
    data = request.get_json()
    if not data or 'ip_address' not in data:
        return jsonify({
            'success': False,
            'error': 'IP address required'
        }), 400

    ip_address = data['ip_address']
    reason = data.get('reason', 'Blocked via SentinelX dashboard')

    # Check if already blocked
    if db.is_ip_blocked(ip_address):
        return jsonify({
            'success': False,
            'error': f'IP {ip_address} is already blocked'
        }), 409

    # Save to database first
    db.block_ip(ip_address, reason)

    # Execute firewall rule
    result = execute_block(ip_address)

    # Notify dashboard via Socket.io
    socketio.emit('ip_blocked', {
        'ip_address': ip_address,
        'reason': reason,
        'method': result['method'],
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    })

    return jsonify({
        'success': True,
        'ip_address': ip_address,
        'method': result['method'],
        'message': result['message']
    })


@app.route('/api/unblock_ip', methods=['POST'])
def unblock_ip():
    """Unblock a previously blocked IP"""
    data = request.get_json()
    if not data or 'ip_address' not in data:
        return jsonify({
            'success': False,
            'error': 'IP address required'
        }), 400

    ip_address = data['ip_address']
    db.unblock_ip(ip_address)

    # Remove firewall rule
    execute_unblock(ip_address)

    socketio.emit('ip_unblocked', {'ip_address': ip_address})

    return jsonify({
        'success': True,
        'message': f'IP {ip_address} unblocked'
    })


@app.route('/api/blocked_ips')
def get_blocked_ips():
    """Return all blocked IPs"""
    return jsonify(db.get_blocked_ips())


def get_voice_assistant():
    """Get or create voice assistant instance"""
    global voice_assistant
    if voice_assistant is None:
        from voice.assistant import VoiceAssistant
        voice_assistant = VoiceAssistant()
    return voice_assistant


@app.route('/api/voice/enable', methods=['POST'])
def enable_voice():
    try:
        va = get_voice_assistant()
        va.enable()
        return jsonify({
            'success': True,
            'message': 'Voice assistant enabled'
        })
    except Exception as e:
        print(f"[VOICE] Enable error: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/voice/disable', methods=['POST'])
def disable_voice():
    global voice_assistant
    if voice_assistant:
        voice_assistant.disable()
    return jsonify({
        'success': True,
        'message': 'Voice assistant disabled'
    })


@app.route('/api/voice/command', methods=['POST'])
def voice_command():
    """Process a typed command through the voice assistant"""
    data = request.get_json()
    if not data:
        return jsonify({
            'success': False,
            'error': 'No data received'
        }), 400

    command = data.get('command', '').strip()
    if not command:
        return jsonify({
            'success': False,
            'error': 'Empty command'
        }), 400

    print(f"[VOICE] Command received from dashboard: {command}")

    # Get or create assistant
    va = get_voice_assistant()

    was_enabled = va.enabled
    va.enabled = True
    response = va.process_command(command)
    va.enabled = was_enabled

    return jsonify({
        'success': True,
        'response': response
    })


@app.route('/api/voice/status')
def voice_status():
    """Return voice assistant status"""
    global voice_assistant
    enabled = voice_assistant is not None and voice_assistant.enabled
    return jsonify({'enabled': enabled})

# SOCKET.IO EVENTS

@socketio.on('connect')
def handle_connect():
    """Client connected to dashboard"""
    print("[DASHBOARD] Client connected to dashboard")
    alerts = db.get_alerts(limit=50)
    stats = db.get_alert_statistics()
    socketio.emit('initial_data', {
        'alerts': alerts,
        'stats': stats
    })


@socketio.on('disconnect')
def handle_disconnect():
    """Client disconnected"""
    print("[DASHBOARD] Client disconnected")


@socketio.on('request_stats')
def handle_stats_request():
    """Client requesting updated statistics"""
    stats = db.get_alert_statistics()
    socketio.emit('stats_update', stats)


def emit_new_alert(alert_data):
    """Push alert to dashboard and trigger voice"""
    socketio.emit('new_alert', alert_data)
    stats = db.get_alert_statistics()
    socketio.emit('stats_update', stats)

    # Voice announcement
    global voice_assistant
    if voice_assistant and voice_assistant.enabled:
        threading.Thread(
            target=voice_assistant.announce_alert,
            args=(alert_data,),
            daemon=True
        ).start()

# FIREWALL HELPER FUNCTIONS

def execute_block(ip_address):
    """
    Execute firewall block command.
    Linux (Ubuntu VM) : iptables
    Windows (dev)     : simulation only
    """
    system = platform.system()

    if system == 'Linux':
        try:
            subprocess.run([
                'iptables', '-A', 'INPUT',
                '-s', ip_address,
                '-j', 'DROP'
            ], check=True, capture_output=True)
            print(f"[BLOCK] iptables rule added for {ip_address}")
            return {
                'method': 'iptables',
                'message': f'IP {ip_address} blocked via iptables'
            }
        except subprocess.CalledProcessError as e:
            print(f"[BLOCK] iptables error: {e}")
            return {
                'method': 'failed',
                'message': f'iptables error: {e}'
            }
        except FileNotFoundError:
            return {
                'method': 'simulation',
                'message': 'iptables not found, logged only'
            }
    else:
        print(f"[BLOCK] Windows mode: {ip_address} logged as blocked")
        print(f"[BLOCK] On Ubuntu VM: iptables rule will be applied")
        return {
            'method': 'simulation',
            'message': (
                f'IP {ip_address} logged as blocked. '
                f'On Ubuntu VM, iptables rule will be applied.'
            )
        }


def execute_unblock(ip_address):
    """Remove firewall block rule"""
    system = platform.system()
    if system == 'Linux':
        try:
            subprocess.run([
                'iptables', '-D', 'INPUT',
                '-s', ip_address,
                '-j', 'DROP'
            ], check=True, capture_output=True)
            print(f"[BLOCK] iptables rule removed for {ip_address}")
        except Exception as e:
            print(f"[BLOCK] Unblock error: {e}")

# RUN

if __name__ == '__main__':
    print("[DASHBOARD] SentinelX Dashboard starting...")
    print("[DASHBOARD] Open http://localhost:5000 in your browser")
    socketio.run(app, host='0.0.0.0', port=5000,
                 debug=False, allow_unsafe_werkzeug=True)