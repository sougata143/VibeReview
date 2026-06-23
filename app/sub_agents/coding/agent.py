# app/sub_agents/coding/agent.py
# Coding sub-agent to execute refactoring, apply fixes, and run verification tests.

from google.adk.agents import Agent
from google.adk.models import Gemini
from google.genai import types

from app.app_utils.typing import schema_manager

def run_sandbox(command: str) -> dict:
    """Mock sandbox command execution tool."""
    return {"status": "success", "execution_output": f"Executed command: {command}"}

def create_coding_agent() -> Agent:
    """Factory function for the Coding sub-agent."""
    role_description = (
        "You are the Coding Agent in a sequential security auditing pipeline. "
        "Read the work tickets and partition plan. Generate the refactored edits, execute "
        "the verification tests, and apply fixes in the gVisor sandbox using your run_sandbox tool. "
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
            model="gemini-3.1-flash-lite",
            retry_options=types.HttpRetryOptions(attempts=6, initial_delay=6.0)
        ),
        instruction=instruction,
        description="Executes code refactoring and fixes.",
        tools=[run_sandbox]
    )

