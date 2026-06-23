# app/sub_agents/search/agent.py
# Search sub-agent to query knowledge graph (GQL) and vector database.

from google.adk.agents import Agent
from google.adk.tools import google_search

def get_search_tool(query: str) -> dict:
    """Mock search tool that returns Knowledge Graph records."""
    return {"status": "success", "results": f"Knowledge Graph results for '{query}'"}

def create_search_agent() -> Agent:
    """Factory function for the Search sub-agent."""
    return Agent(
        name="search_agent",
        model="gemini-2.5-flash",
        instruction="""You are the Search Agent. Your job is to search the Spanner Graph database using your get_search_tool to find structural details, code files, and potential vulnerabilities based on the user request. Pass your search results down the pipeline.""",
        description="Searches code structure and metadata in Spanner Graph.",
        tools=[get_search_tool]
    )
