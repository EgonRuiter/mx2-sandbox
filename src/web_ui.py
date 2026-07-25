# ruff: noqa: E501, W293
"""MX2 Embedded Web UI Admin Dashboard Generator.

Generates a responsive single-page HTML5/CSS3/JS dark-mode Admin Console
for live telemetry monitoring, quarantine queue management, DID key lookups,
and envelope translation testing.
"""


def get_admin_dashboard_html() -> str:
    """Returns the complete single-page HTML content for the /admin dashboard."""
    return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MX2 Protocol Daemon — Admin Console</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Fira+Code:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-primary: #0b0f19;
            --bg-secondary: #111827;
            --bg-card: #1f293d;
            --accent-blue: #3b82f6;
            --accent-cyan: #06b6d4;
            --accent-green: #10b981;
            --accent-yellow: #f59e0b;
            --accent-red: #ef4444;
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
            --border-color: #374151;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Inter', sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-main);
            line-height: 1.5;
            padding: 24px;
        }
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 20px;
            border-bottom: 1px solid var(--border-color);
            margin-bottom: 24px;
        }
        .logo-title { display: flex; align-items: center; gap: 12px; }
        .logo-badge {
            background: linear-gradient(135deg, var(--accent-blue), var(--accent-cyan));
            color: #fff;
            font-weight: 700;
            padding: 6px 12px;
            border-radius: 8px;
            font-size: 0.9rem;
        }
        .status-pill {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            background: rgba(16, 185, 129, 0.15);
            color: var(--accent-green);
            padding: 6px 12px;
            border-radius: 20px;
            font-weight: 600;
            font-size: 0.85rem;
        }
        .status-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--accent-green); }
        
        .kpi-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
            margin-bottom: 32px;
        }
        .kpi-card {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 20px;
        }
        .kpi-label { font-size: 0.85rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; }
        .kpi-value { font-size: 1.8rem; font-weight: 700; margin-top: 8px; color: #fff; }

        .section-title { font-size: 1.25rem; font-weight: 600; margin-bottom: 16px; display: flex; align-items: center; gap: 8px; }
        
        .panel {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 32px;
        }
        table { width: 100%; border-collapse: collapse; text-align: left; }
        th, td { padding: 12px 16px; border-bottom: 1px solid var(--border-color); font-size: 0.9rem; }
        th { color: var(--text-muted); font-weight: 500; text-transform: uppercase; font-size: 0.75rem; }
        tr:last-child td { border-bottom: none; }
        
        .btn {
            cursor: pointer;
            border: none;
            padding: 8px 14px;
            border-radius: 6px;
            font-weight: 600;
            font-size: 0.85rem;
            transition: opacity 0.2s;
        }
        .btn:hover { opacity: 0.85; }
        .btn-approve { background: var(--accent-green); color: #fff; }
        .btn-reject { background: var(--accent-red); color: #fff; }
        .btn-primary { background: var(--accent-blue); color: #fff; width: 100%; padding: 12px; }

        textarea, input {
            width: 100%;
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            color: var(--text-main);
            padding: 12px;
            border-radius: 8px;
            font-family: 'Fira Code', monospace;
            font-size: 0.85rem;
            margin-bottom: 16px;
        }
        pre {
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            padding: 16px;
            border-radius: 8px;
            font-family: 'Fira Code', monospace;
            font-size: 0.85rem;
            color: var(--accent-cyan);
            overflow-x: auto;
        }
    </style>
</head>
<body>
    <header>
        <div class="logo-title">
            <div class="logo-badge">MX2 DAEMON</div>
            <h2>Admin Control Console</h2>
        </div>
        <div class="status-pill">
            <span class="status-dot"></span>
            DAEMON RUNNING (v2.0.0)
        </div>
    </header>

    <div class="kpi-grid">
        <div class="kpi-card">
            <div class="kpi-label">API Calls Resolved</div>
            <div class="kpi-value" id="kpi-api-calls">-</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-label">Quarantined Emails</div>
            <div class="kpi-value" id="kpi-quarantine" style="color: var(--accent-yellow)">-</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-label">Verified PoWs</div>
            <div class="kpi-value" id="kpi-pow" style="color: var(--accent-green)">-</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-label">Decrypted Envelopes</div>
            <div class="kpi-value" id="kpi-decrypted" style="color: var(--accent-cyan)">-</div>
        </div>
    </div>

    <div class="panel">
        <div class="section-title">🚨 Grade E Quarantine Holding Queue</div>
        <table>
            <thead>
                <tr>
                    <th>Message ID</th>
                    <th>Sender Address</th>
                    <th>Subject Line</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody id="quarantine-tbody">
                <tr><td colspan="4" style="text-align: center; color: var(--text-muted);">Loading quarantine queue...</td></tr>
            </tbody>
        </table>
    </div>

    <div class="panel">
        <div class="section-title">⚡ Interactive SMTP to MX2 E2EE Envelope Translator</div>
        <label style="display:block; margin-bottom: 8px; font-size:0.85rem; color:var(--text-muted);">Paste Legacy SMTP MIME String:</label>
        <textarea id="translate-input" rows="5">From: alice@example.com
To: did:mx2:MCowBQYDK2VwAyEAdS+7fGZ8A1839gBbcD81hS9bV2g327
Subject: Web UI Interactive Test
Content-Type: text/plain

Hello from the MX2 Web Admin Dashboard!</textarea>
        <button class="btn btn-primary" onclick="translateEmail()">Translate to Sealed Sender Envelope</button>
        <div style="margin-top: 16px;">
            <label style="display:block; margin-bottom: 8px; font-size:0.85rem; color:var(--text-muted);">Output Envelope Payload:</label>
            <pre id="translate-output">// Encrypted MX2 envelope JSON will appear here...</pre>
        </div>
    </div>

    <script>
        async function fetchMetrics() {
            try {
                const res = await fetch('/metrics');
                const text = await res.text();
                const parseVal = (key) => {
                    const match = text.match(new RegExp(`${key}\\\\s+(\\\\d+)`));
                    return match ? match[1] : '0';
                };
                document.getElementById('kpi-api-calls').innerText = parseVal('mx2_api_requests_total');
                document.getElementById('kpi-quarantine').innerText = parseVal('mx2_quarantine_count');
                document.getElementById('kpi-pow').innerText = parseVal('mx2_pow_verified_total');
                document.getElementById('kpi-decrypted').innerText = parseVal('mx2_decrypted_messages_total');
            } catch (err) { console.error('Error fetching metrics', err); }
        }

        async function fetchQueue() {
            try {
                const res = await fetch('/api/queue/list');
                const data = await res.json();
                const tbody = document.getElementById('quarantine-tbody');
                if (!data.queue || data.queue.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--accent-green);">No quarantined emails in queue! All senders verified.</td></tr>';
                    return;
                }
                tbody.innerHTML = data.queue.map(item => `
                    <tr>
                        <td><code>${item.messageId}</code></td>
                        <td>${item.sender}</td>
                        <td>${item.subject}</td>
                        <td>
                            <button class="btn btn-approve" onclick="approveMsg('${item.messageId}')">Approve & Whitelist</button>
                            <button class="btn btn-reject" onclick="rejectMsg('${item.messageId}')">Discard</button>
                        </td>
                    </tr>
                `).join('');
            } catch (err) { console.error('Error fetching queue', err); }
        }

        async function approveMsg(id) {
            await fetch('/api/queue/approve', { method: 'POST', body: JSON.stringify({ messageId: id }) });
            fetchQueue(); fetchMetrics();
        }

        async function rejectMsg(id) {
            await fetch('/api/queue/reject', { method: 'POST', body: JSON.stringify({ messageId: id }) });
            fetchQueue(); fetchMetrics();
        }

        async function translateEmail() {
            const smtp = document.getElementById('translate-input').value;
            const res = await fetch('/api/translate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ smtp: smtp })
            });
            const data = await res.json();
            document.getElementById('translate-output').innerText = JSON.stringify(data, null, 2);
            fetchMetrics();
        }

        fetchMetrics();
        fetchQueue();
        setInterval(() => { fetchMetrics(); fetchQueue(); }, 5000);
    </script>
</body>
</html>
"""
