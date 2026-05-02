/**
 * SentinelX - Dashboard Controller
 * Handles real-time updates via Socket.io
 */

const socket = io();
let hourlyChart = null;
let typeChart   = null;
let allAlerts   = [];

// ── CONNECTION ──
socket.on('connect', () => {
    console.log('SentinelX: Connected to server');
    updateTimestamp();
});

socket.on('initial_data', (data) => {
    allAlerts = data.alerts || [];
    renderAlerts(allAlerts);
    updateStats(data.stats);
    loadSSHEvents();
});

socket.on('new_alert', (alert) => {
    allAlerts.unshift(alert);
    renderAlerts(allAlerts);
    showNotification(alert);
    socket.emit('request_stats');
});

socket.on('stats_update', (stats) => {
    updateStats(stats);
});

socket.on('ip_blocked', (data) => {
    console.log('IP blocked:', data.ip_address);
    updateBlockButtons(data.ip_address);
});


// ── RENDER ALERTS TABLE ──
function renderAlerts(alerts) {
    const tbody = document.getElementById('alerts-table');
    const badge = document.getElementById('alert-count-badge');

    badge.textContent = alerts.length;

    if (!alerts || !alerts.length) {
        tbody.innerHTML = `
            <tr>
                <td colspan="6">
                    <div class="empty-state">
                        System is monitoring — no alerts detected yet
                    </div>
                </td>
            </tr>`;
        return;
    }

    // Fetch blocked IPs first, then render
    fetch('/api/blocked_ips')
        .then(r => r.json())
        .then(blockedList => {
            const blockedSet = new Set(
                blockedList.map(b => b.ip_address)
            );

            tbody.innerHTML = alerts.map((a, i) => {
                const safeId = a.ip_address.replace(/\./g, '-');
                const isBlocked = blockedSet.has(a.ip_address);

                const actionBtn = isBlocked
                    ? `<div class="d-flex gap-1">
                        <button class="btn-blocked" disabled>
                            Blocked
                        </button>
                        <button
                            class="btn-unblock"
                            onclick="unblockIP('${a.ip_address}')">
                            Unblock
                        </button>
                       </div>`
                    : `<button
                            id="block-btn-${safeId}"
                            class="btn-block"
                            onclick="blockIP('${a.ip_address}')">
                            Block IP
                       </button>`;

                return `
                <tr class="${i === 0 ? 'alert-new' : ''}">
                    <td>
                        <span class="sev-badge
                              sev-${a.severity.toLowerCase()}">
                            ${a.severity}
                        </span>
                    </td>
                    <td>
                        <span class="ip-addr">${a.ip_address}</span>
                    </td>
                    <td>
                        <span class="${attackClass(a.attack_type)}">
                            ${attackLabel(a.attack_type)}
                        </span>
                    </td>
                    <td>
                        <span class="details-text">
                            ${a.details || '-'}
                        </span>
                    </td>
                    <td>
                        <span class="ts-text">${a.timestamp}</span>
                    </td>
                    <td>${actionBtn}</td>
                </tr>`;
            }).join('');
        })
        .catch(() => {
            // Fallback sans vérification blocked
            tbody.innerHTML = alerts.map((a, i) => {
                const safeId = a.ip_address.replace(/\./g, '-');
                return `
                <tr class="${i === 0 ? 'alert-new' : ''}">
                    <td>
                        <span class="sev-badge
                              sev-${a.severity.toLowerCase()}">
                            ${a.severity}
                        </span>
                    </td>
                    <td>
                        <span class="ip-addr">${a.ip_address}</span>
                    </td>
                    <td>
                        <span class="${attackClass(a.attack_type)}">
                            ${attackLabel(a.attack_type)}
                        </span>
                    </td>
                    <td>
                        <span class="details-text">
                            ${a.details || '-'}
                        </span>
                    </td>
                    <td>
                        <span class="ts-text">${a.timestamp}</span>
                    </td>
                    <td>
                        <button
                            id="block-btn-${safeId}"
                            class="btn-block"
                            onclick="blockIP('${a.ip_address}')">
                            Block IP
                        </button>
                    </td>
                </tr>`;
            }).join('');
        });
}


// ── BLOCK IP ──
function blockIP(ipAddress) {
    const safeId = ipAddress.replace(/\./g, '-');
    const btn = document.getElementById('block-btn-' + safeId);

    if (!confirm(
        'Block IP address ' + ipAddress + '?\n\n' +
        'This will prevent further connections from this address.'
    )) return;

    if (btn) {
        btn.textContent = 'Blocking...';
        btn.disabled = true;
    }

    fetch('/api/block_ip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            ip_address: ipAddress,
            reason: 'Blocked via SentinelX dashboard'
        })
    })
    .then(r => r.json())
    .then(data => {
        if (data.success) {
            // Re-render ALL alerts to update ALL buttons
            // for this IP (multiple rows same IP)
            renderAlerts(allAlerts);
            showBlockNotification(ipAddress, data.message);
        } else {
            if (btn) {
                btn.textContent = 'Block IP';
                btn.disabled = false;
            }
            alert('Error: ' + (data.error || 'Unknown error'));
        }
    })
    .catch(err => {
        if (btn) {
            btn.textContent = 'Block IP';
            btn.disabled = false;
        }
        alert('Request failed: ' + err.message);
    });
}


// ── UNBLOCK IP ──
function unblockIP(ipAddress) {
    if (!confirm(
        'Unblock IP address ' + ipAddress + '?\n\n' +
        'This IP will be able to connect again.'
    )) return;

    fetch('/api/unblock_ip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip_address: ipAddress })
    })
    .then(r => r.json())
    .then(data => {
        if (data.success) {
            // Re-render alerts to update all buttons
            renderAlerts(allAlerts);
            showUnblockNotification(ipAddress);
        } else {
            alert('Error: ' + (data.error || 'Unknown error'));
        }
    })
    .catch(err => {
        alert('Request failed: ' + err.message);
    });
}


function showUnblockNotification(ipAddress) {
    const div = document.createElement('div');
    div.style.cssText = `
        position: fixed;
        top: 70px;
        right: 20px;
        z-index: 9999;
        background: #388bfd;
        color: white;
        padding: 12px 20px;
        border-radius: 8px;
        font-weight: 600;
        font-size: 0.88rem;
        box-shadow: 0 4px 16px rgba(0,0,0,0.6);
        min-width: 220px;
    `;
    div.innerHTML = `
        <div style="font-size:0.72rem;margin-bottom:3px;opacity:0.8">
            IP UNBLOCKED
        </div>
        <div>${ipAddress}</div>
        <div style="font-size:0.78rem;margin-top:3px;opacity:0.8">
            This IP can now connect again
        </div>
    `;
    document.body.appendChild(div);
    setTimeout(() => div.remove(), 5000);
}


function updateBlockButtons(ipAddress) {
    const safeId = ipAddress.replace(/\./g, '-');
    const btn = document.getElementById('block-btn-' + safeId);
    if (btn) {
        btn.textContent = 'Blocked';
        btn.style.backgroundColor = '#238636';
        btn.disabled = true;
    }
}

function showBlockNotification(ipAddress, message) {
    const div = document.createElement('div');
    div.style.cssText = `
        position: fixed;
        top: 70px;
        right: 20px;
        z-index: 9999;
        background: #238636;
        color: white;
        padding: 12px 20px;
        border-radius: 8px;
        font-weight: 600;
        font-size: 0.88rem;
        box-shadow: 0 4px 16px rgba(0,0,0,0.6);
        min-width: 220px;
    `;
    div.innerHTML = `
        <div style="font-size:0.72rem;margin-bottom:3px;opacity:0.8">
            IP BLOCKED
        </div>
        <div>${ipAddress}</div>
        <div style="font-size:0.78rem;margin-top:3px;opacity:0.8">
            ${message}
        </div>
    `;
    document.body.appendChild(div);
    setTimeout(() => div.remove(), 5000);
}

// VOICE ASSISTANT

let recognition    = null;
let isListening    = false;
let voiceEnabled   = false;

// ── TOGGLE VOICE ──
function toggleVoice(enabled) {
    const endpoint = enabled
        ? '/api/voice/enable'
        : '/api/voice/disable';

    const label = document.getElementById('voice-status-label');
    const panel = document.getElementById('voice-panel');

    fetch(endpoint, { method: 'POST' })
        .then(r => r.json())
        .then(data => {
            if (data.success) {
                voiceEnabled = enabled;
                if (enabled) {
                    if (label) {
                        label.textContent  = 'Enabled';
                        label.style.color  = '#3fb950';
                    }
                    if (panel) panel.style.display = 'block';
                    initSpeechRecognition();
                } else {
                    if (label) {
                        label.textContent  = 'Disabled';
                        label.style.color  = '#6e7681';
                    }
                    if (panel) panel.style.display = 'none';
                    stopListening();
                }
            } else {
                alert('Voice error: ' + data.error);
                document.getElementById(
                    'voice-toggle').checked = !enabled;
            }
        })
        .catch(err => {
            alert('Voice request failed: ' + err.message);
            document.getElementById(
                'voice-toggle').checked = !enabled;
        });
}


// ── INIT SPEECH RECOGNITION ──
function initSpeechRecognition() {
    // Check browser support
    const SpeechRecognition =
        window.SpeechRecognition ||
        window.webkitSpeechRecognition;

    if (!SpeechRecognition) {
        document.getElementById('mic-status').textContent =
            'Microphone not supported in this browser. Use Chrome.';
        document.getElementById('mic-status').style.color =
            '#da3633';
        return;
    }

    recognition = new SpeechRecognition();
    recognition.lang            = 'en-US';
    recognition.continuous      = false;
    recognition.interimResults  = false;
    recognition.maxAlternatives = 1;

    // When speech is recognized
    recognition.onresult = function(event) {
        const transcript =
            event.results[0][0].transcript;
        console.log('[VOICE] Heard:', transcript);

        // Show what was heard
        const transcriptEl =
            document.getElementById('voice-transcript');
        if (transcriptEl) {
            transcriptEl.textContent  = transcript;
            transcriptEl.style.color  = '#e6edf3';
            transcriptEl.style.fontStyle = 'normal';
        }

        // Send to backend
        sendCommand(transcript);
        stopListening();
    };

    recognition.onerror = function(event) {
        console.error('[VOICE] Error:', event.error);
        const micStatus =
            document.getElementById('mic-status');

        if (event.error === 'not-allowed') {
            if (micStatus) {
                micStatus.textContent =
                    'Microphone access denied. ' +
                    'Please allow microphone in browser.';
                micStatus.style.color = '#da3633';
            }
        } else if (event.error === 'no-speech') {
            if (micStatus) {
                micStatus.textContent = 'No speech detected. Try again.';
                micStatus.style.color = '#e3b341';
            }
        } else {
            if (micStatus) {
                micStatus.textContent = 'Error: ' + event.error;
                micStatus.style.color = '#da3633';
            }
        }
        stopListening();
    };

    recognition.onend = function() {
        if (isListening) stopListening();
    };
}


// ── TOGGLE MIC ──
function toggleMic() {
    if (isListening) {
        stopListening();
    } else {
        startListening();
    }
}

function startListening() {
    if (!recognition) {
        initSpeechRecognition();
    }
    if (!recognition) return;

    isListening = true;

    const btn    = document.getElementById('mic-btn');
    const status = document.getElementById('mic-status');

    if (btn) {
        btn.style.background   = '#da3633';
        btn.style.borderColor  = '#da3633';
        btn.style.color        = 'white';
        btn.innerHTML          = '🔴';
    }
    if (status) {
        status.textContent = 'Listening... speak now';
        status.style.color = '#3fb950';
    }

    try {
        recognition.start();
    } catch(e) {
        console.error('[VOICE] Start error:', e);
        stopListening();
    }
}

function stopListening() {
    isListening = false;

    const btn    = document.getElementById('mic-btn');
    const status = document.getElementById('mic-status');

    if (btn) {
        btn.style.background  = '#1c2128';
        btn.style.borderColor = '#30363d';
        btn.style.color       = '#8b949e';
        btn.innerHTML         = '🎤';
    }
    if (status) {
        status.textContent = 'Click to speak';
        status.style.color = '#6e7681';
    }

    if (recognition) {
        try { recognition.stop(); } catch(e) {}
    }
}


// ── SEND COMMAND TO BACKEND ──
function sendCommand(command) {
    const responseEl =
        document.getElementById('voice-response');

    if (responseEl) {
        responseEl.textContent = 'Processing...';
        responseEl.style.color = '#8b949e';
    }

    fetch('/api/voice/command', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ command: command })
    })
    .then(r => r.json())
    .then(data => {
        if (data.success) {
            if (responseEl) {
                responseEl.textContent = data.response;
                responseEl.style.color = '#3fb950';
            }
        } else {
            if (responseEl) {
                responseEl.textContent =
                    'Error: ' + (data.error || 'Unknown');
                responseEl.style.color = '#da3633';
            }
        }
    })
    .catch(err => {
        if (responseEl) {
            responseEl.textContent =
                'Request failed: ' + err.message;
            responseEl.style.color = '#da3633';
        }
    });
}


// ── TYPED COMMAND FALLBACK ──
function sendVoiceCommand() {
    const input   =
        document.getElementById('voice-command-input');
    const command = input.value.trim();

    if (!command) {
        alert('Please type a command');
        return;
    }

    // Show in transcript area
    const transcriptEl =
        document.getElementById('voice-transcript');
    if (transcriptEl) {
        transcriptEl.textContent   = command;
        transcriptEl.style.color   = '#e6edf3';
        transcriptEl.style.fontStyle = 'normal';
    }

    sendCommand(command);
    input.value = '';
}

function handleVoiceKey(event) {
    if (event.key === 'Enter') sendVoiceCommand();
}


// ── UPDATE STATS ──
function updateStats(stats) {
    if (!stats) return;

    const critical = (stats.by_severity['Critical'] || 0)
                   + (stats.by_severity['High'] || 0);

    document.getElementById('total-alerts').textContent =
        stats.total || 0;
    document.getElementById('critical-alerts').textContent =
        critical;
    document.getElementById('brute-count').textContent =
        stats.by_type['BRUTE_FORCE'] || 0;
    document.getElementById('scan-count').textContent =
        stats.by_type['PORT_SCAN'] || 0;
    document.getElementById('alert-count-badge').textContent =
        stats.total || 0;

    updateTimestamp();
    buildHourlyChart(stats.per_hour || []);
    buildTypeChart(stats.by_type || {});
    renderTopIPs(stats.top_ips || []);
}


// ── HOURLY CHART ──
function buildHourlyChart(perHour) {
    const labels = Array.from({length: 24}, (_, i) =>
        String(i).padStart(2, '0') + ':00');
    const data = new Array(24).fill(0);
    perHour.forEach(item => {
        data[parseInt(item.hour)] = item.count;
    });

    if (hourlyChart) {
        hourlyChart.data.datasets[0].data = data;
        hourlyChart.update('none');
        return;
    }

    const ctx = document.getElementById('hourlyChart').getContext('2d');
    hourlyChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Number of Alerts',
                data: data,
                backgroundColor: 'rgba(163, 113, 247, 0.5)',
                borderColor: '#a371f7',
                borderWidth: 1,
                borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: { display: false },
                tooltip: {
                    callbacks: {
                        label: function(ctx) {
                            return ' ' + ctx.parsed.y +
                                   ' alert(s) at ' + ctx.label;
                        }
                    }
                }
            },
            scales: {
                x: {
                    ticks: {
                        color: '#8b949e',
                        font: { size: 10 }
                    },
                    grid: { color: '#21262d' }
                },
                y: {
                    ticks: {
                        color: '#8b949e',
                        stepSize: 1,
                        font: { size: 10 }
                    },
                    grid: { color: '#21262d' },
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: 'Alert Count',
                        color: '#8b949e',
                        font: { size: 11 }
                    }
                }
            }
        }
    });
}


// ── TYPE CHART ──
function buildTypeChart(byType) {
    const entries = Object.entries(byType);
    const legend  = document.getElementById('type-legend');
    const empty   = document.getElementById('type-empty');

    if (!entries.length) {
        if (typeChart) {
            typeChart.destroy();
            typeChart = null;
        }
        if (legend) legend.innerHTML = '';
        if (empty)  empty.style.display = 'block';
        return;
    }

    if (empty) empty.style.display = 'none';

    const labels = entries.map(function(e) {
        return attackLabel(e[0]);
    });
    const data = entries.map(function(e) {
        return e[1];
    });
    const colors = ['#e3b341', '#388bfd', '#da3633', '#3fb950'];

    if (legend) {
        legend.innerHTML = entries.map(function(e, i) {
            return '<div class="d-flex justify-content-between' +
                   ' align-items-center mb-1">' +
                   '<span style="color:' + colors[i] + ';' +
                   'font-size:0.82rem;font-weight:600">' +
                   attackLabel(e[0]) + '</span>' +
                   '<span style="color:#8b949e;font-size:0.82rem">' +
                   e[1] + ' alert(s)</span></div>';
        }).join('');
    }

    if (typeChart) {
        typeChart.data.labels = labels;
        typeChart.data.datasets[0].data = data;
        typeChart.update('none');
        return;
    }

    const ctx = document.getElementById('typeChart').getContext('2d');
    typeChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: data,
                backgroundColor: colors,
                borderWidth: 2,
                borderColor: '#161b22'
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: { display: false },
                tooltip: {
                    callbacks: {
                        label: function(ctx) {
                            return ' ' + ctx.label +
                                   ': ' + ctx.parsed + ' alert(s)';
                        }
                    }
                }
            }
        }
    });
}


// ── TOP IPs ──
function renderTopIPs(topIPs) {
    const list = document.getElementById('top-ips');

    if (!topIPs || !topIPs.length) {
        list.innerHTML = '<li class="list-group-item">' +
            '<div class="empty-state">No attackers detected yet</div>' +
            '</li>';
        return;
    }

    const max = topIPs[0].count;
    list.innerHTML = topIPs.map(function(item, i) {
        const pct = Math.round(item.count / max * 100);
        return '<li class="list-group-item">' +
            '<div class="d-flex justify-content-between' +
            ' align-items-center mb-1">' +
            '<div>' +
            '<span style="color:#8b949e;font-size:0.78rem;' +
            'margin-right:8px">#' + (i + 1) + '</span>' +
            '<span class="ip-addr">' + item.ip_address + '</span>' +
            '</div>' +
            '<span style="color:#da3633;font-weight:700;' +
            'font-size:0.88rem">' + item.count +
            ' alert' + (item.count > 1 ? 's' : '') + '</span>' +
            '</div>' +
            '<div class="progress" style="height:4px;margin-top:4px">' +
            '<div class="progress-bar" style="width:' + pct + '%;' +
            'background-color:#da3633"></div>' +
            '</div></li>';
    }).join('');
}


// ── SSH EVENTS ──
function loadSSHEvents() {
    fetch('/api/ssh_events')
        .then(function(r) { return r.json(); })
        .then(function(events) {
            const tbody = document.getElementById('ssh-table');
            if (!events || !events.length) {
                tbody.innerHTML = '<tr><td colspan="4">' +
                    '<div class="empty-state">' +
                    'No SSH attempts recorded yet</div></td></tr>';
                return;
            }
            tbody.innerHTML = events.map(function(e) {
                return '<tr>' +
                    '<td><span class="ip-addr">' +
                    e.ip_address + '</span></td>' +
                    '<td><span class="cred-user">' +
                    e.username + '</span></td>' +
                    '<td><span class="cred-pass">' +
                    e.password + '</span></td>' +
                    '<td><span class="ts-text">' +
                    e.timestamp + '</span></td>' +
                    '</tr>';
            }).join('');
        })
        .catch(function() {});
}


// ── FILTER ALERTS ──
function filterAlerts(severity) {
    const filtered = severity === 'all'
        ? allAlerts
        : allAlerts.filter(function(a) {
            return a.severity === severity;
          });
    renderAlerts(filtered);
}


// ── EXPORT CSV ──
function exportCSV() {
    fetch('/api/export/csv')
        .then(function(response) {
            if (!response.ok) {
                throw new Error('No data to export');
            }
            return response.blob();
        })
        .then(function(blob) {
            const url = window.URL.createObjectURL(blob);
            const a   = document.createElement('a');
            a.href    = url;
            const today = new Date().toISOString().slice(0, 10);
            a.download = 'sentinelx_alerts_' + today + '.csv';
            document.body.appendChild(a);
            a.click();
            a.remove();
            window.URL.revokeObjectURL(url);
        })
        .catch(function(err) {
            alert('Export failed: ' + err.message);
        });
}


// ── NOTIFICATION ──
function showNotification(alert) {
    const colors = {
        Critical: '#da3633',
        High:     '#e3b341',
        Medium:   '#388bfd',
        Low:      '#238636'
    };
    const div = document.createElement('div');
    div.style.cssText =
        'position:fixed;top:70px;right:20px;z-index:9999;' +
        'background:' + (colors[alert.severity] || '#333') + ';' +
        'color:' + (alert.severity === 'High' ? '#000' : '#fff') + ';' +
        'padding:12px 20px;border-radius:8px;' +
        'font-weight:600;font-size:0.88rem;' +
        'box-shadow:0 4px 16px rgba(0,0,0,0.6);min-width:220px;';
    div.innerHTML =
        '<div style="font-size:0.72rem;opacity:0.8;margin-bottom:3px">' +
        'NEW ALERT DETECTED</div>' +
        '<div>' + alert.severity + ' — ' +
        attackLabel(alert.attack_type) + '</div>' +
        '<div style="font-family:monospace;font-size:0.82rem;' +
        'margin-top:3px">' + alert.ip_address + '</div>';
    document.body.appendChild(div);
    setTimeout(function() { div.remove(); }, 4000);
}


// ── HELPERS ──
function attackLabel(type) {
    if (type === 'BRUTE_FORCE') return 'Brute Force SSH';
    if (type === 'PORT_SCAN')   return 'Port Scan';
    return type;
}

function attackClass(type) {
    return type === 'BRUTE_FORCE' ? 'attack-brute' : 'attack-scan';
}

function updateTimestamp() {
    const el = document.getElementById('last-updated');
    if (el) {
        el.textContent = 'Last updated: ' +
            new Date().toLocaleTimeString();
    }
}


// ── AUTO-REFRESH ──
setInterval(function() {
    socket.emit('request_stats');
    loadSSHEvents();
}, 5000);