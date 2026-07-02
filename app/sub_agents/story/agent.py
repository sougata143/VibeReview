# app/sub_agents/story/agent.py
# Story sub-agent to capture requirements and context.

from google.adk.agents import Agent
from google.adk.models import Gemini
from google.genai import types
from app.config import Config

def get_epic_details(epic_id: str) -> dict:
    """Mock epic fetching tool."""
    return {"status": "success", " epic_context": f"Epic requirements for '{epic_id}'"}

def create_story_agent() -> Agent:
    """Factory function for the Story sub-agent."""
    return Agent(
        name="story_agent",
        model=Gemini(
            model=Config.PRO_MODEL,
            retry_options=types.HttpRetryOptions(attempts=6, initial_delay=6.0)
        ),
        instruction="""You are the Story Agent in a sequential security auditing pipeline. Read the search findings from the search_agent. Use your get_epic_details tool to fetch and extract epic requirements and context for any related tasks or tickets. Summarize requirements for the next agent.""",
        description="Captures epic requirements.",
        tools=[get_epic_details]
    )
