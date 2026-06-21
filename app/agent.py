# app/agent.py
# Root Orchestrator definition for VibeReview.
# Coordinates the sub-agent pipeline (Search -> Story -> Impact -> Task-Breakdown -> Coding).

from google.adk.workflow import Workflow
from app.sub_agents.search.agent import create_search_agent
from app.sub_agents.story.agent import create_story_agent
from app.sub_agents.impact.agent import create_impact_agent
from app.sub_agents.task_breakdown.agent import create_task_breakdown_agent
from app.sub_agents.coding.agent import create_coding_agent

def create_root_agent() -> Workflow:
    """Factory function for the VibeReview main orchestrator agent workflow.
    
    Wires the discrete sub-agents in a sequential graph pipeline using the graph-native 
    ADK Workflow class:
    1. **Search**: Queries Spanner Graph database using GQL / GQL vector search.
    2. **Story**: Translates tickets and parse requirements.
    3. **Impact**: Predicts vulnerabilities downstream code side-effects.
    4. **Task-Breakdown**: Partitions work into tickets.
    5. **Coding**: Generates refactored script modifications inside isolated sandboxes.
    """
    search_agent = create_search_agent()
    story_agent = create_story_agent()
    impact_agent = create_impact_agent()
    task_breakdown_agent = create_task_breakdown_agent()
    coding_agent = create_coding_agent()
    
    # Establish edges representing execution sequences between nodes.
    # The runner drives the session state from START node down to subsequent nodes.
    return Workflow(
        name="vibe_review_pipeline",
        description="Continuous code auditor pipeline (Search -> Story -> Impact -> Task-Breakdown -> Coding)",
        edges=[
            ('START', search_agent),
            (search_agent, story_agent),
            (story_agent, impact_agent),
            (impact_agent, task_breakdown_agent),
            (task_breakdown_agent, coding_agent)
        ]
    )

# Root agent hook for agents-cli / ADK runtimes
root_agent = create_root_agent()

# Define the App container matching the directory name 'app' and register the security plugin
from google.adk.apps import App
from app.security import RedBlueGreenSecurityPlugin

# The App name MUST match the directory containing the agent (e.g. "app")
# to ensure the ADK runner and CLI session manager locate the execution endpoints.
# The security plugin intercepts all tool calls invoked across the workflow.
app = App(
    name="app",
    root_agent=root_agent,
    plugins=[RedBlueGreenSecurityPlugin()]
)
