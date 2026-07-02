# app/sub_agents/coding/agent.py
# Coding sub-agent to execute refactoring, apply fixes, and run verification tests.

import subprocess
from google.adk.agents import Agent
from google.adk.models import Gemini
from google.genai import types
from app.config import Config
from app.app_utils.typing import schema_manager

def execute_sandbox(command: str) -> dict:
    """Executes a command inside the sandbox (local environment shell) to verify code/tests.
    
    Args:
        command: The shell command to run in the local environment sandbox.
    """
    import re
    import os
    from app.sandbox_gating import validate_code

    # 1. Check for Python script executions in the command
    python_files = re.findall(r'\b([\w\-./]+\.py)\b', command)
    for py_file in python_files:
        if os.path.exists(py_file):
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    code = f.read()
                gating_errors = validate_code(code, py_file)
                if gating_errors:
                    return {
                        "status": "failed_gating",
                        "error": f"Dynamic Sandboxing Gating Blocked Execution on '{py_file}' due to security/lint checks.",
                        "gating_errors": gating_errors
                    }
            except Exception as e:
                pass

    # 2. Check for inline python scripts (-c "...")
    inline_match = re.search(r'python3?\s+-c\s+["\'](.*?)["\']', command)
    if inline_match:
        inline_code = inline_match.group(1)
        gating_errors = validate_code(inline_code, "<inline>")
        if gating_errors:
            return {
                "status": "failed_gating",
                "error": "Dynamic Sandboxing Gating Blocked Execution on inline script due to security/lint checks.",
                "gating_errors": gating_errors
            }

    try:
        res = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30
        )
        return {
            "status": "success" if res.returncode == 0 else "failed",
            "returncode": res.returncode,
            "stdout": res.stdout,
            "stderr": res.stderr
        }
    except subprocess.TimeoutExpired:
        return {
            "status": "timeout",
            "error": "Command execution timed out after 30 seconds."
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}

def create_coding_agent() -> Agent:
    """Factory function for the Coding sub-agent."""
    role_description = (
        "You are the Coding Agent in a sequential security auditing pipeline. "
        "Read the work tickets and partition plan. Generate the refactored edits, execute "
        "the verification tests, and apply fixes in the gVisor sandbox using your execute_sandbox tool. "
        "Additionally, you must construct an A2UI JSON payload summarizing the changes made "
        "using only the allowed components: Card, List, Text, and Button. You must emit this A2UI payload "
        "wrapped in <a2ui-json> and </a2ui-json> tags within your response."
    )
    instruction = schema_manager.generate_system_prompt(
        role_description=role_description,
        allowed_components=["Card", "List", "Text", "Button"],
        include_schema=True
    ).replace("{expression}", "[expression]")
    return Agent(
        name="coding_agent",
        model=Gemini(
            model=Config.DEFAULT_MODEL,
            retry_options=types.HttpRetryOptions(attempts=6, initial_delay=6.0)
        ),
        instruction=instruction,
        description="Executes code refactoring and fixes.",
        tools=[execute_sandbox]
    )

