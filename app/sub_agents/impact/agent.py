# app/sub_agents/impact/agent.py
# Impact sub-agent to predict side-effects of vulnerabilities or proposed changes.

from google.adk.agents import Agent

def get_impact_tool(target: str) -> dict:
    """Mock impact tool that scans dependency graphs."""
    return {"status": "success", "impact_assessment": f"Low risk side-effects for '{target}'"}

def create_impact_agent() -> Agent:
    """Factory function for the Impact sub-agent."""
    return Agent(
        name="impact_agent",
        model="gemini-1.5-flash",
        instruction="Analyze the given vulnerability or code modification and predict downstream side-effects.",
        description="Assesses call-graphs and side-effect impacts.",
        tools=[get_impact_tool]
    )
