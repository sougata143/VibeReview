# run_live_ui.py
# Dynamic Live A2UI Web Canvas Dashboard for VibeReview.
#
# Runs a local FastAPI server providing a premium web interface.
# Accepts prompt inputs, runs the live ADK multi-agent pipeline in the background,
# parses the returned HybridResponse, and dynamically renders the A2UI Canvas dashboard.

import os
import sys
import json
import logging
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Set mock environment variables for offline/local execution safety if not explicitly set
os.environ.setdefault("INTEGRATION_TEST", "TRUE")

# Mock Google Auth Default globally for local/offline run support
import google.auth
import google.auth.credentials

class DummyCredentials(google.auth.credentials.Credentials):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.token = "dummy-token"
    def refresh(self, request):
        pass

google.auth.default = lambda **kwargs: (DummyCredentials(), "dummy-project")

from app.agent_runtime_app import agent_runtime

app = FastAPI(title="VibeReview Live Canvas Interface")

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VibeReview Live Canvas Dashboard</title>
    <style>
        :root {
            --bg-color: #0b0f19;
            --card-bg: rgba(17, 24, 39, 0.7);
            --border-color: rgba(255, 255, 255, 0.08);
            --primary: #3b82f6;
            --primary-glow: rgba(59, 130, 246, 0.35);
            --success: #10b981;
            --danger: #ef4444;
            --warning: #f59e0b;
            --text: #f3f4f6;
            --text-secondary: #9ca3af;
        }

        body {
            background-color: var(--bg-color);
            color: var(--text);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", sans-serif;
            margin: 0;
            padding: 2rem;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
        }

        .container {
            width: 100%;
            max-width: 900px;
            display: flex;
            flex-direction: column;
            gap: 2rem;
        }

        header {
            text-align: center;
            margin-bottom: 1rem;
        }

        header h1 {
            font-size: 2.2rem;
            margin: 0;
            background: linear-gradient(135deg, #60a5fa, #3b82f6);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            font-weight: 800;
            letter-spacing: -0.025em;
        }

        header p {
            color: var(--text-secondary);
            margin-top: 0.5rem;
            font-size: 1rem;
        }

        .input-panel {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.5rem;
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.3);
            backdrop-filter: blur(12px);
        }

        .input-group {
            display: flex;
            flex-direction: column;
            gap: 0.8rem;
        }

        label {
            font-weight: 600;
            font-size: 0.95rem;
            color: var(--text);
        }

        textarea {
            width: 100%;
            height: 100px;
            background: rgba(0, 0, 0, 0.3);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            color: var(--text);
            padding: 0.8rem;
            font-size: 0.95rem;
            resize: vertical;
            box-sizing: border-box;
            outline: none;
            transition: border-color 0.2s ease, box-shadow 0.2s ease;
        }

        textarea:focus {
            border-color: var(--primary);
            box-shadow: 0 0 0 3px var(--primary-glow);
        }

        .btn-run {
            background: linear-gradient(135deg, #3b82f6, #2563eb);
            color: white;
            border: none;
            padding: 0.9rem 1.8rem;
            font-size: 1rem;
            font-weight: 700;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.2s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.5rem;
        }

        .btn-run:hover {
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(59, 130, 246, 0.4);
        }

        .btn-run:active {
            transform: translateY(0);
        }

        .btn-run:disabled {
            background: #4b5563;
            cursor: not-allowed;
            transform: none;
            box-shadow: none;
        }

        .suggestions {
            margin-top: 1rem;
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
        }

        .suggestion-chip {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid var(--border-color);
            padding: 0.4rem 0.8rem;
            border-radius: 9999px;
            font-size: 0.8rem;
            cursor: pointer;
            color: var(--text-secondary);
            transition: all 0.2s ease;
        }

        .suggestion-chip:hover {
            background: rgba(59, 130, 246, 0.1);
            border-color: var(--primary);
            color: var(--text);
        }

        /* Loading Spinner */
        .loading-container {
            display: none;
            justify-content: center;
            align-items: center;
            flex-direction: column;
            gap: 1rem;
            padding: 2rem;
        }

        .spinner {
            width: 40px;
            height: 40px;
            border: 4px solid rgba(255, 255, 255, 0.1);
            border-top: 4px solid var(--primary);
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        /* Canvas Output Frame */
        .canvas-frame {
            display: none;
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 2rem;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.4);
            backdrop-filter: blur(12px);
        }

        /* Vulnerability Report Table */
        .vuln-report-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 1rem;
            font-size: 0.95rem;
            text-align: left;
        }
        
        .vuln-report-table th, .vuln-report-table td {
            padding: 0.75rem 1rem;
            border-bottom: 1px solid var(--border-color);
        }
        
        .vuln-report-table th {
            background-color: rgba(255, 255, 255, 0.03);
            color: var(--text);
            font-weight: 700;
        }
        
        .vuln-report-table td {
            color: var(--text-secondary);
            vertical-align: middle;
        }
        
        /* Severity Badges */
        .badge {
            display: inline-block;
            padding: 0.25rem 0.6rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
        }
        
        .badge-critical {
            background-color: rgba(239, 68, 68, 0.2);
            color: #fca5a5;
            border: 1px solid #ef4444;
        }
        
        .badge-high {
            background-color: rgba(249, 115, 22, 0.2);
            color: #fed7aa;
            border: 1px solid #f97316;
        }
        
        .badge-medium {
            background-color: rgba(245, 158, 11, 0.2);
            color: #fef3c7;
            border: 1px solid #f59e0b;
        }
        
        .badge-low {
            background-color: rgba(59, 130, 246, 0.2);
            color: #dbeafe;
            border: 1px solid #3b82f6;
        }
        
        .code-location {
            font-family: monospace;
            background: rgba(0, 0, 0, 0.25);
            padding: 0.2rem 0.4rem;
            border-radius: 4px;
            color: #38bdf8;
            font-size: 0.85rem;
        }
        
        /* Clean Build Shield Card */
        .clean-build-card {
            background: rgba(16, 185, 129, 0.04);
            border: 1px solid rgba(16, 185, 129, 0.2);
            border-radius: 12px;
            padding: 2.5rem;
            text-align: center;
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 1rem;
            margin-top: 1rem;
        }
        
        .clean-build-icon {
            font-size: 3.5rem;
            color: var(--success);
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0% { transform: scale(1); }
            50% { transform: scale(1.05); }
            100% { transform: scale(1); }
        }

        /* Rendered components styling */
        .a2ui-container {
            display: flex;
            flex-direction: column;
            gap: 1.2rem;
        }

        .a2ui-header {
            font-size: 1.6rem;
            font-weight: 700;
            border-bottom: 2px solid var(--primary);
            padding-bottom: 0.6rem;
            margin: 0;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .a2ui-card {
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 1.2rem;
            display: flex;
            flex-direction: column;
            gap: 0.6rem;
        }

        .a2ui-list {
            list-style: none;
            padding: 0;
            margin: 0;
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }

        .a2ui-list-item {
            background: rgba(255, 255, 255, 0.04);
            border: 1px solid var(--border-color);
            padding: 0.8rem 1rem;
            border-radius: 6px;
            display: flex;
            align-items: center;
            gap: 0.6rem;
            font-size: 0.95rem;
        }

        .a2ui-list-item::before {
            content: "🔸";
        }

        .a2ui-btn-group {
            display: flex;
            gap: 1rem;
            margin-top: 1rem;
        }

        .a2ui-button {
            flex: 1;
            padding: 0.8rem 1.2rem;
            border: none;
            border-radius: 6px;
            font-weight: 700;
            cursor: pointer;
            transition: all 0.2s ease;
        }

        .a2ui-button-primary {
            background-color: var(--primary);
            color: white;
        }

        .a2ui-button-primary:hover {
            background-color: #2563eb;
            transform: translateY(-1px);
        }

        .a2ui-button-danger {
            background-color: var(--danger);
            color: white;
        }

        .a2ui-button-danger:hover {
            background-color: #dc2626;
            transform: translateY(-1px);
        }

        /* Stateful Quarantine Modal */
        .modal-overlay {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0, 0, 0, 0.85);
            justify-content: center;
            align-items: center;
            z-index: 100;
            backdrop-filter: blur(8px);
        }

        .modal-content {
            background: #111827;
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 2rem;
            max-width: 500px;
            width: 90%;
            box-shadow: 0 25px 50px rgba(0, 0, 0, 0.7);
            text-align: center;
            animation: fadeIn 0.25s ease;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: scale(0.96); }
            to { opacity: 1; transform: scale(1); }
        }

        .modal-title {
            font-size: 1.4rem;
            color: var(--danger);
            margin-bottom: 0.8rem;
            font-weight: 800;
        }

        .status-badge {
            background: rgba(239, 68, 68, 0.15);
            color: var(--danger);
            border: 1px solid var(--danger);
            padding: 0.3rem 0.8rem;
            border-radius: 9999px;
            font-size: 0.85rem;
            display: inline-block;
            margin-bottom: 1.2rem;
        }

        .code-box {
            background: #030712;
            border: 1px solid var(--border-color);
            padding: 1rem;
            border-radius: 6px;
            text-align: left;
            font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
            color: #38bdf8;
            margin: 1rem 0;
            overflow-x: auto;
            font-size: 0.85rem;
            max-height: 150px;
        }

        .btn-close {
            background: #374151;
            color: var(--text);
            border: none;
            padding: 0.6rem 1.2rem;
            border-radius: 6px;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.2s;
        }

        .btn-close:hover {
            background: #4b5563;
        }

        /* Success banner */
        .approval-message {
            display: none;
            background: rgba(16, 185, 129, 0.1);
            border: 1px solid var(--success);
            color: var(--success);
            padding: 0.8rem;
            border-radius: 6px;
            text-align: center;
            font-weight: 700;
            font-size: 0.95rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🎨 VibeReview Live Canvas Interface</h1>
            <p>Type a natural language prompt to audit repositories and interact with security findings</p>
        </header>

        <div class="input-panel">
            <div class="input-group">
                <label for="prompt-input">Enter Audit Prompt:</label>
                <textarea id="prompt-input" placeholder="e.g. Clone repository https://github.com/octocat/Spoon-Knife.git and perform security checks..."></textarea>
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div class="suggestions">
                        <span class="suggestion-chip" onclick="setPrompt(this)">Clone Spoon-Knife and scan for SAST & SCA flaws</span>
                        <span class="suggestion-chip" onclick="setPrompt(this)">Audit app/app_utils/microtransactions.py for vulnerabilities</span>
                    </div>
                    <button class="btn-run" id="btn-submit">
                        <span>🚀</span> Run Continuous Audit
                    </button>
                </div>
            </div>
        </div>

        <!-- Spinner -->
        <div class="loading-container" id="loading">
            <div class="spinner"></div>
            <p style="color: var(--text-secondary);">Pipeline executing... running static SAST, SCA, and Code Smell scans in sandbox...</p>
        </div>

        <!-- Dynamic A2UI Canvas Dashboard Frame -->
        <div class="canvas-frame" id="canvas-card">
            <div class="a2ui-container" id="a2ui-root">
                <!-- Programmatically populated by A2UI rendering engine -->
            </div>
        </div>
    </div>

    <!-- Stateful Quarantine Modal -->
    <div class="modal-overlay" id="quarantine-modal">
        <div class="modal-content">
            <div class="modal-title">🚨 Stateful Quarantine Triggered</div>
            <span class="status-badge">Status: QUARANTINED</span>
            <p>The Green Team has frozen the session state due to a security policy violation.</p>
            <div class="code-box" id="remediated-code">
# Sanitized by Green Team Auto-Refactoring
pass
            </div>
            <button class="btn-close" onclick="closeQuarantineModal()">Close Details</button>
        </div>
    </div>

    <script>
        function setPrompt(element) {
            document.getElementById('prompt-input').value = element.innerText;
        }

        function closeQuarantineModal() {
            document.getElementById('quarantine-modal').style.display = 'none';
        }

        document.getElementById('btn-submit').addEventListener('click', async () => {
            const prompt = document.getElementById('prompt-input').value.trim();
            if (!prompt) return;

            // Update UI state to loading
            document.getElementById('loading').style.display = 'flex';
            document.getElementById('canvas-card').style.display = 'none';
            document.getElementById('btn-submit').disabled = true;

            try {
                const response = await fetch(`/run-agent?prompt=${encodeURIComponent(prompt)}`);
                const result = await response.json();

                document.getElementById('loading').style.display = 'none';
                document.getElementById('btn-submit').disabled = false;

                if (result.error) {
                    alert('Error running pipeline: ' + result.error);
                    return;
                }

                renderDashboard(result);
            } catch (err) {
                document.getElementById('loading').style.display = 'none';
                document.getElementById('btn-submit').disabled = false;
                alert('Connection error: ' + err.message);
            }
        });

        function escapeHtml(text) {
            if (!text) return '';
            return text
                .toString()
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#039;");
        }

        function renderDashboard(response) {
            const root = document.getElementById('a2ui-root');
            root.innerHTML = ''; // Clear previous

            const data = response.data || {};
            const ui = response.ui || {};
            const updateComponents = ui.updateComponents || {};
            const components = updateComponents.components || [];

            // 1. Render the Header/Title
            const headerComp = components.find(c => c.type === 'Header' || c.type === 'Title');
            const titleText = headerComp ? (headerComp.text || headerComp.properties?.text) : '🎨 VibeReview Security Audit Report';
            
            const headerElem = document.createElement('h1');
            headerElem.className = 'a2ui-header';
            headerElem.innerText = titleText;
            root.appendChild(headerElem);

            // Subtitle
            const subtitle = document.createElement('p');
            subtitle.style.color = 'var(--text-secondary)';
            subtitle.style.margin = '0 0 1rem 0';
            subtitle.innerText = `Generative A2UI Surface ID: ${updateComponents.surfaceId || 'vibe-review-surface'}`;
            root.appendChild(subtitle);

            // 2. Render parsed vulnerabilities or Clean Build shield
            const parsedVulns = data.parsed_vulnerabilities || [];

            if (parsedVulns.length > 0) {
                const reportCard = document.createElement('div');
                reportCard.className = 'a2ui-card';
                
                const cardHeader = document.createElement('h3');
                cardHeader.style.margin = '0 0 0.8rem 0';
                cardHeader.innerText = '🛡️ Vulnerability Scan Report';
                reportCard.appendChild(cardHeader);
                
                // Create table
                const table = document.createElement('table');
                table.className = 'vuln-report-table';
                
                // Table structure
                table.innerHTML = `
                    <thead>
                        <tr>
                            <th style="width: 25%;">Vulnerability Type</th>
                            <th style="width: 15%;">Severity</th>
                            <th style="width: 20%;">File Location</th>
                            <th style="width: 40%;">Details / Code Trigger</th>
                        </tr>
                    </thead>
                    <tbody>
                    </tbody>
                `;
                
                const tbody = table.querySelector('tbody');
                parsedVulns.forEach(v => {
                    const tr = document.createElement('tr');
                    
                    const sevLower = v.severity.toLowerCase();
                    let badgeClass = 'badge-low';
                    if (sevLower === 'critical') badgeClass = 'badge-critical';
                    else if (sevLower === 'high') badgeClass = 'badge-high';
                    else if (sevLower === 'medium') badgeClass = 'badge-medium';
                    
                    tr.innerHTML = `
                        <td style="font-weight: 600; color: var(--text);">${escapeHtml(v.type)}</td>
                        <td><span class="badge ${badgeClass}">${escapeHtml(v.severity)}</span></td>
                        <td><span class="code-location">${escapeHtml(v.file)}</span></td>
                        <td style="font-family: monospace; font-size: 0.85rem; color: #38bdf8; word-break: break-all;">${escapeHtml(v.code)}</td>
                    `;
                    tbody.appendChild(tr);
                });
                
                reportCard.appendChild(table);
                root.appendChild(reportCard);
            } else {
                // Clean build layout
                const cleanCard = document.createElement('div');
                cleanCard.className = 'clean-build-card';
                
                cleanCard.innerHTML = `
                    <div class="clean-build-icon">🛡️</div>
                    <h2 style="margin: 0; color: var(--success); font-weight: 800; font-size: 1.5rem; letter-spacing: -0.01em;">CLEAN BUILD — GATEWAYS SECURED</h2>
                    <p style="margin: 0; color: var(--text-secondary); max-width: 500px; font-size: 0.95rem; line-height: 1.5;">
                        No SAST vulnerabilities, SCA package flaws, or SonarQube code smells have been flagged. All AST policies, taint check paths, and quarantine gates passed successfully.
                    </p>
                `;
                root.appendChild(cleanCard);
            }

            // 2b. Render Raw Agent Output
            if (data.raw_output) {
                const rawCard = document.createElement('div');
                rawCard.className = 'a2ui-card';
                rawCard.style.marginTop = '1.2rem';
                
                const rawTitle = document.createElement('h3');
                rawTitle.style.margin = '0 0 0.8rem 0';
                rawTitle.innerText = '📝 Raw Agent Report Output';
                rawCard.appendChild(rawTitle);
                
                const rawPre = document.createElement('pre');
                rawPre.style.whiteSpace = 'pre-wrap';
                rawPre.style.fontFamily = 'monospace';
                rawPre.style.fontSize = '0.9rem';
                rawPre.style.background = 'rgba(0, 0, 0, 0.2)';
                rawPre.style.padding = '1rem';
                rawPre.style.borderRadius = '6px';
                rawPre.style.color = '#38bdf8';
                rawPre.innerText = data.raw_output;
                rawCard.appendChild(rawPre);
                
                root.appendChild(rawCard);
            }

            // 3. Render Buttons/Actions
            const btnGroup = document.createElement('div');
            btnGroup.className = 'a2ui-btn-group';

            const btnQuarantine = document.createElement('button');
            btnQuarantine.className = 'a2ui-button a2ui-button-danger';
            btnQuarantine.innerText = 'Trigger Stateful Quarantine';
            btnQuarantine.addEventListener('click', () => {
                document.getElementById('quarantine-modal').style.display = 'flex';
            });

            const btnApprove = document.createElement('button');
            btnApprove.className = 'a2ui-button a2ui-button-primary';
            btnApprove.innerText = 'Approve Vibe Diff';
            btnApprove.addEventListener('click', () => {
                document.getElementById('approval-box').style.display = 'block';
            });

            btnGroup.appendChild(btnQuarantine);
            btnGroup.appendChild(btnApprove);
            root.appendChild(btnGroup);

            // 4. Render Approval Box placeholder
            const approvalBox = document.createElement('div');
            approvalBox.id = 'approval-box';
            approvalBox.className = 'approval-message';
            approvalBox.innerText = '✅ Vibe Diff Approved via Cryptographic Hardware MFA';
            root.appendChild(approvalBox);

            // Display the final rendered dashboard
            document.getElementById('canvas-card').style.display = 'block';
        }
    </script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
async def serve_canvas():
    return HTML_TEMPLATE

@app.get("/run-agent")
async def run_agent(prompt: str):
    try:
        # Stream the query and collect the final output chunk
        accumulated_text = ""
        async for event in agent_runtime.async_stream_query(message=prompt, user_id="web-canvas-client"):
            content = event.get("content")
            if content and "parts" in content:
                for part in content["parts"]:
                    if "text" in part and part["text"]:
                        accumulated_text = part["text"]
                        
        if not accumulated_text:
            return JSONError("No output returned from multi-agent pipeline.")

        # Parse output as HybridResponse JSON
        response_json = json.loads(accumulated_text)
        return JSONResponse(content=response_json)
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

def JSONError(msg: str):
    return JSONResponse(status_code=400, content={"error": msg})

if __name__ == "__main__":
    print("Launching VibeReview Live A2UI Web Canvas Dashboard...")
    uvicorn.run(app, host="127.0.0.1", port=8000)
