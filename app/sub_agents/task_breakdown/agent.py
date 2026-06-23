# app/sub_agents/task_breakdown/agent.py
# Task-Breakdown sub-agent to produce atomic units of work.

from google.adk.agents import Agent

def create_work_tickets(tasks: list) -> dict:
    """Mock ticket creation tool."""
    return {"status": "success", "tickets_created": len(tasks)}

def create_task_breakdown_agent() -> Agent:
    """Factory function for the Task-Breakdown sub-agent."""
    return Agent(
        name="task_breakdown_agent",
        model="gemini-2.5-flash",
        instruction="""You are the Task-Breakdown Agent in a sequential security auditing pipeline. Read the vulnerability impact assessment. Partition the required refactoring work into atomic tasks and create work tickets using your create_work_tickets tool.""",
        description="Breaks down work into tickets.",
        tools=[create_work_tickets]
    )
