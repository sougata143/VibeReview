# tests/a2ui_server.py
from fastapi import FastAPI
from fastapi.responses import HTMLResponse

app = FastAPI()

HTML_CONTENT = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>A2UI Canvas Dashboard</title>
    <style>
        :root {
            --bg-color: #0f172a;
            --card-bg: rgba(30, 41, 59, 0.7);
            --border-color: rgba(255, 255, 255, 0.1);
            --primary: #3b82f6;
            --success: #10b981;
            --danger: #ef4444;
            --text: #f8fafc;
            --text-secondary: #94a3b8;
        }

        body {
            background-color: var(--bg-color);
            color: var(--text);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            margin: 0;
            padding: 2rem;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }

        .dashboard-container {
            width: 100%;
            max-width: 600px;
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 2rem;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
            backdrop-filter: blur(10px);
        }

        h1 {
            font-size: 1.8rem;
            margin-bottom: 1.5rem;
            border-bottom: 2px solid var(--primary);
            padding-bottom: 0.5rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        ul {
            list-style: none;
            padding: 0;
            margin: 1.5rem 0;
        }

        li {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid var(--border-color);
            padding: 0.8rem 1rem;
            border-radius: 6px;
            margin-bottom: 0.5rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        li::before {
            content: "🔸";
        }

        .btn-group {
            display: flex;
            gap: 1rem;
            margin-top: 1.5rem;
        }

        button {
            flex: 1;
            padding: 0.8rem 1.2rem;
            border: none;
            border-radius: 6px;
            font-weight: bold;
            cursor: pointer;
            transition: all 0.2s ease;
        }

        .btn-primary {
            background-color: var(--primary);
            color: white;
        }

        .btn-primary:hover {
            background-color: #2563eb;
            transform: translateY(-1px);
        }

        .btn-danger {
            background-color: var(--danger);
            color: white;
        }

        .btn-danger:hover {
            background-color: #dc2626;
            transform: translateY(-1px);
        }

        /* Modal styling */
        .modal-overlay {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0, 0, 0, 0.8);
            justify-content: center;
            align-items: center;
            z-index: 100;
            backdrop-filter: blur(5px);
        }

        .modal-content {
            background: #1e293b;
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 2rem;
            max-width: 450px;
            width: 90%;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.8);
            text-align: center;
            animation: fadeIn 0.3s ease;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: scale(0.95); }
            to { opacity: 1; transform: scale(1); }
        }

        .modal-title {
            font-size: 1.5rem;
            color: var(--danger);
            margin-bottom: 1rem;
            font-weight: bold;
        }

        .status-badge {
            background: rgba(239, 68, 68, 0.2);
            color: var(--danger);
            border: 1px solid var(--danger);
            padding: 0.3rem 0.8rem;
            border-radius: 9999px;
            font-size: 0.9rem;
            display: inline-block;
            margin-bottom: 1rem;
        }

        .code-box {
            background: #090d16;
            border: 1px solid var(--border-color);
            padding: 1rem;
            border-radius: 6px;
            text-align: left;
            font-family: monospace;
            color: #38bdf8;
            margin: 1rem 0;
            overflow-x: auto;
        }

        .btn-close {
            background: var(--text-secondary);
            color: var(--bg-color);
        }

        /* Approval message */
        .approval-message {
            display: none;
            margin-top: 1rem;
            background: rgba(16, 185, 129, 0.1);
            border: 1px solid var(--success);
            color: var(--success);
            padding: 0.8rem;
            border-radius: 6px;
            text-align: center;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <div class="dashboard-container" id="root">
        <h1 id="title">🎨 VibeReview Security Audit Report</h1>
        <p style="color: var(--text-secondary);">Generative A2UI Surface ID: vibe-review-surface</p>
        
        <ul id="vulnerabilities_list">
            <li>User Enumeration in login responses</li>
            <li>Weak SHA-256 Hashing for passwords</li>
            <li>7-day long JWT Token Expiration policy</li>
        </ul>

        <div class="btn-group">
            <button id="btn-quarantine" class="btn-danger">Trigger Stateful Quarantine</button>
            <button id="btn-approve" class="btn-primary">Approve Vibe Diff</button>
        </div>

        <div id="approval-box" class="approval-message">
            ✅ Vibe Diff Approved via Cryptographic Hardware MFA
        </div>
    </div>

    <!-- Quarantine Modal -->
    <div class="modal-overlay" id="quarantine-modal">
        <div class="modal-content">
            <div class="modal-title">🚨 Stateful Quarantine Triggered</div>
            <span class="status-badge" id="status-badge">Status: QUARANTINED</span>
            <p>The Green Team has frozen the session state due to a security policy violation.</p>
            <div class="code-box">
# Sanitized by Green Team Auto-Refactoring
pass
            </div>
            <button id="btn-close-modal" class="btn-close">Close Details</button>
        </div>
    </div>

    <script>
        const btnQuarantine = document.getElementById('btn-quarantine');
        const btnApprove = document.getElementById('btn-approve');
        const btnCloseModal = document.getElementById('btn-close-modal');
        const modal = document.getElementById('quarantine-modal');
        const approvalBox = document.getElementById('approval-box');

        btnQuarantine.addEventListener('click', () => {
            modal.style.display = 'flex';
        });

        btnCloseModal.addEventListener('click', () => {
            modal.style.display = 'none';
        });

        btnApprove.addEventListener('click', () => {
            approvalBox.style.display = 'block';
        });
    </script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
async def get_dashboard():
    return HTML_CONTENT
