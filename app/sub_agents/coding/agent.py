# app/sub_agents/coding/agent.py
# Coding sub-agent to execute refactoring, apply fixes, and run verification tests.

from google.adk.agents import Agent
from google.adk.models import Gemini
from google.genai import types

def run_sandbox(command: str) -> dict:
    """Mock sandbox command execution tool."""
    return {"status": "success", "execution_output": f"Executed command: {command}"}

def create_coding_agent() -> Agent:
    """Factory function for the Coding sub-agent."""
    return Agent(
        name="coding_agent",
        model=Gemini(
            model="gemini-3.1-flash-lite",
            retry_options=types.HttpRetryOptions(attempts=6, initial_delay=6.0)
        ),
        instruction="""You are the Coding Agent in a sequential security auditing pipeline. Read the work tickets and partition plan. Generate the refactored edits, execute the verification tests, and apply fixes in the gVisor sandbox using your run_sandbox tool.""",
        description="Executes code refactoring and fixes.",
        tools=[run_sandbox]
    )
