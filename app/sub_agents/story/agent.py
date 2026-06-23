# app/sub_agents/story/agent.py
# Story sub-agent to capture requirements and context.

from google.adk.agents import Agent

def get_epic_details(epic_id: str) -> dict:
    """Mock epic fetching tool."""
    return {"status": "success", " epic_context": f"Epic requirements for '{epic_id}'"}

def create_story_agent() -> Agent:
    """Factory function for the Story sub-agent."""
    return Agent(
        name="story_agent",
        model="gemini-flash-latest",
        instruction="Capture ticket and user requirements for the context of audits.",
        description="Captures epic requirements.",
        tools=[get_epic_details]
    )
