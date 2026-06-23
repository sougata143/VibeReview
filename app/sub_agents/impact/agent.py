# app/sub_agents/impact/agent.py
# Impact sub-agent to predict side-effects of vulnerabilities or proposed changes.

from google.adk.agents import Agent
from google.adk.models import Gemini
from google.genai import types

def get_impact_tool(target: str) -> dict:
    """Mock impact tool that scans dependency graphs."""
    return {"status": "success", "impact_assessment": f"Low risk side-effects for '{target}'"}

def create_impact_agent() -> Agent:
    """Factory function for the Impact sub-agent."""
    return Agent(
        name="impact_agent",
        model=Gemini(
            model="gemini-3.1-flash-lite",
            retry_options=types.HttpRetryOptions(attempts=6, initial_delay=6.0)
        ),
        instruction="""You are the Impact Agent in a sequential security auditing pipeline. Read the search findings and user stories from previous steps. Use your get_impact_tool to scan dependency graphs and assess downstream side-effects of any identified vulnerabilities or proposed modifications. Pass your impact assessment to the next agent.""",
        description="Assesses call-graphs and side-effect impacts.",
        tools=[get_impact_tool]
    )
