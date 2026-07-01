# app/sub_agents/impact/agent.py
# Impact sub-agent to predict side-effects of vulnerabilities or proposed changes.

from google.adk.agents import Agent
from google.adk.models import Gemini
from google.genai import types
from app.config import Config
from app.app_utils.typing import schema_manager

def get_impact_tool(target: str) -> dict:
    """Mock impact tool that scans dependency graphs."""
    return {"status": "success", "impact_assessment": f"Low risk side-effects for '{target}'"}

def create_impact_agent() -> Agent:
    """Factory function for the Impact sub-agent."""
    role_description = (
        "You are the Impact Agent in a sequential security auditing pipeline. "
        "Read the search findings and user stories from previous steps. Use your get_impact_tool "
        "to scan dependency graphs and assess downstream side-effects of any identified "
        "vulnerabilities or proposed modifications. Pass your impact assessment to the next agent. "
        "Additionally, you must construct an A2UI JSON payload summarizing your impact findings "
        "using only the allowed components: Card, List, Text, and Button. You must emit this A2UI payload "
        "wrapped in <a2ui-json> and </a2ui-json> tags within your response."
    )
    instruction = schema_manager.generate_system_prompt(
        role_description=role_description,
        allowed_components=["Card", "List", "Text", "Button"],
        include_schema=True
    ).replace("{expression}", "[expression]")
    return Agent(
        name="impact_agent",
        model=Gemini(
            model=Config.DEFAULT_MODEL,
            retry_options=types.HttpRetryOptions(attempts=6, initial_delay=6.0)
        ),
        instruction=instruction,
        description="Assesses call-graphs and side-effect impacts.",
        tools=[get_impact_tool]
    )

