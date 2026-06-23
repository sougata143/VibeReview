# app/sub_agents/search/agent.py
# Search sub-agent to query knowledge graph (GQL) and vector database.

from google.adk.agents import Agent
from google.adk.tools import google_search
from google.adk.models import Gemini
from google.genai import types

def get_search_tool(query: str) -> dict:
    """Mock search tool that returns Knowledge Graph records."""
    return {"status": "success", "results": f"Knowledge Graph results for '{query}'"}

def create_search_agent() -> Agent:
    """Factory function for the Search sub-agent."""
    return Agent(
        name="search_agent",
        model=Gemini(
            model="gemini-3.1-flash-lite",
            retry_options=types.HttpRetryOptions(attempts=6, initial_delay=6.0)
        ),
        instruction="""You are the Search Agent. Your job is to search the Spanner Graph database using your get_search_tool to find structural details, code files, and potential vulnerabilities based on the user request. Pass your search results down the pipeline.""",
        description="Searches code structure and metadata in Spanner Graph.",
        tools=[get_search_tool]
    )
