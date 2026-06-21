# tests/unit/test_quarantine.py
# Test-Driven Development (TDD): Unit test for Green Team's Stateful Quarantine.

import pytest
from google.adk.agents import Agent
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types

from app.security import (
    SecurityAnomalyException,
    QuarantinedStateException,
    RedBlueGreenSecurityPlugin
)

class MockTool:
    def __init__(self, name: str):
        self.name = name

class MockToolContext:
    def __init__(self, state: dict):
        self.state = state

@pytest.mark.asyncio
async def test_stateful_quarantine_flow():
    # 1. Create sub-agents with tools
    def search_db(query: str) -> dict:
        return {"status": "success", "results": f"Found: {query}"}

    def scan_impact(target: str) -> dict:
        return {"status": "success", "impact": "low"}

    def run_sandbox(command: str) -> dict:
        return {"status": "success", "output": f"Executed: {command}"}

    search_agent = Agent(
        name="search_agent",
        tools=[search_db],
        instruction="Explore the knowledge graph database.",
        description="Explores structural code database."
    )
    impact_agent = Agent(
        name="impact_agent",
        tools=[scan_impact],
        instruction="Predict side-effects of vulnerabilities.",
        description="Predicts side-effects."
    )
    coding_agent = Agent(
        name="coding_agent",
        tools=[run_sandbox],
        instruction="Execute refactoring and apply fixes.",
        description="Executes refactoring."
    )

    from google.adk.workflow import Workflow

    pipeline = Workflow(
        name="vibe_review_pipeline",
        edges=[
            ('START', search_agent),
            (search_agent, impact_agent),
            (impact_agent, coding_agent)
        ]
    )

    # 2. Configure session service and runner with Red/Blue/Green security plugin
    session_service = InMemorySessionService()
    session = await session_service.create_session(
        app_name="vibe-review",
        user_id="dev-user",
        session_id="session-quarantine-test"
    )

    plugin = RedBlueGreenSecurityPlugin()
    
    # 3. Simulate tool calls and test plugin behavior directly
    tool = MockTool(name="run_sandbox")
    mock_tool_context = MockToolContext(state=session.state)
    
    # Verify clean tool call passes
    res = await plugin.before_tool_callback(
        tool=tool,
        tool_args={"command": "echo 'hello'"},
        tool_context=mock_tool_context
    )
    assert res is None  # Continue execution
    assert session.state.get("agent_status") != "QUARANTINED"
    
    # 4. Step 2: Trigger anomaly (Red Team payload 'rm -rf')
    with pytest.raises(SecurityAnomalyException) as exc_info:
        await plugin.before_tool_callback(
            tool=tool,
            tool_args={"command": "rm -rf /"},
            tool_context=mock_tool_context
        )
    assert "Security Anomaly" in str(exc_info.value)
    
    # Verify Green Team quarantined the agent and froze state
    assert session.state.get("agent_status") == "QUARANTINED"
    assert session.state.get("remediation_triggered") is True
    assert session.state.get("offending_tool") == "run_sandbox"
    assert "remediated_script" in session.state
    
    # 5. Step 3: Verify revoked tool access (Subsequent call throws QuarantinedStateException)
    with pytest.raises(QuarantinedStateException) as exc_info_quarantine:
        await plugin.before_tool_callback(
            tool=tool,
            tool_args={"command": "echo 'should fail'"},
            tool_context=mock_tool_context
        )
    assert "quarantined" in str(exc_info_quarantine.value).lower()
