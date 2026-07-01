# app/sub_agents/task_breakdown/agent.py
# Task-Breakdown sub-agent to produce atomic units of work.

from google.adk.agents import Agent
from google.adk.models import Gemini
from google.genai import types
from app.config import Config

def create_work_tickets(tasks: list) -> dict:
    """Mock ticket creation tool."""
    return {"status": "success", "tickets_created": len(tasks)}

def create_task_breakdown_agent() -> Agent:
    """Factory function for the Task-Breakdown sub-agent."""
    return Agent(
        name="task_breakdown_agent",
        model=Gemini(
            model=Config.DEFAULT_MODEL,
            retry_options=types.HttpRetryOptions(attempts=6, initial_delay=6.0)
        ),
        instruction="""You are the Task-Breakdown Agent in a sequential security auditing pipeline. Read the vulnerability impact assessment. Partition the required refactoring work into atomic tasks and create work tickets using your create_work_tickets tool.""",
        description="Breaks down work into tickets.",
        tools=[create_work_tickets]
    )
