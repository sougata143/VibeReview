#!/usr/bin/env python3
# run_standalone.py
# Standalone headless runner for CLI / CI-CD execution.

import sys
import json
import os
from dotenv import load_dotenv

# Load environment variables from .env
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

def run_pipeline(prompt: str):
    print(f"Running VibeReview pipeline with prompt: '{prompt}'...")
    
    # Stream the query and capture event outputs
    accumulated_text = ""
    for event in agent_runtime.stream_query(message=prompt, user_id="standalone-runner"):
        content = event.get("content")
        if content and "parts" in content:
            for part in content["parts"]:
                if "text" in part and part["text"]:
                    accumulated_text = part["text"]  # The final event text contains the structured HybridResponse JSON
                    
    if not accumulated_text:
        print("Error: No response received from the agent pipeline.", file=sys.stderr)
        sys.exit(1)
        
    try:
        # Parse the JSON string
        response_json = json.loads(accumulated_text)
    except json.JSONDecodeError as e:
        print(f"Error: Pipeline response was not valid JSON: {e}", file=sys.stderr)
        print(f"Raw response: {accumulated_text}", file=sys.stderr)
        sys.exit(1)
        
    # Extract data block while explicitly ignoring "ui" and "ui_available"
    data = response_json.get("data", {})
    vulnerabilities_found = data.get("vulnerabilities_found", False)
    raw_output = data.get("raw_output", "")
    metrics = data.get("metrics", {})
    
    # Print the raw metrics and diagnostic findings directly to stdout
    print("\n" + "="*60)
    print("           VIBEREVIEW SYSTEM DIAGNOSTICS & METRICS")
    print("="*60)
    print(f"Vulnerabilities Identified: {vulnerabilities_found}")
    print("\nSecurity Metrics:")
    for metric_name, flag in metrics.items():
        status = "⚠️  VULNERABILITY DETECTED" if flag else "✅ SAFE"
        print(f"  - {metric_name.replace('_', ' ').title()}: {status}")
    print("\nRaw Audit Details:")
    print(raw_output)
    print("="*60 + "\n")
    
    # Generate the Markdown summary block for GitHub PR posting
    md_content = []
    md_content.append("## 🔍 VibeReview Automated Security Audit Report")
    md_content.append("")
    status_icon = "❌ **Vulnerabilities Identified**" if vulnerabilities_found else "✅ **No Critical Vulnerabilities Found**"
    md_content.append(f"### Status: {status_icon}")
    md_content.append("")
    md_content.append("### Code Quality & Security Metrics")
    md_content.append("| Metric | Status |")
    md_content.append("| :--- | :--- |")
    for metric_name, flag in metrics.items():
        icon = "⚠️  Vulnerability Flagged" if flag else "✅ Safe"
        md_content.append(f"| {metric_name.replace('_', ' ').title()} | {icon} |")
    md_content.append("")
    md_content.append("### Summary of Findings")
    md_content.append("```markdown")
    md_content.append(raw_output)
    md_content.append("```")
    md_content.append("")
    md_content.append("> _Report generated automatically by VibeReview Continuous Code Auditor pipeline._")
    
    markdown_report = "\n".join(md_content)
    
    # Write the markdown output to disk
    pr_comment_file = "pr_security_report.md"
    with open(pr_comment_file, "w", encoding="utf-8") as f:
        f.write(markdown_report)
        
    print(f"Successfully generated markdown report: {pr_comment_file}")

if __name__ == "__main__":
    default_prompt = "Verify the user authentication module for any code flaws, inspect the requirements context, and run a safe test script in the sandbox."
    query_prompt = sys.argv[1] if len(sys.argv) > 1 else default_prompt
    run_pipeline(query_prompt)
