# tests/unit/test_security.py
# Unit tests for ContextResolver and PolicyServer.

import pytest
from app.context import ContextResolver
from app.security import PolicyServer

def test_context_resolver_email():
    resolver = ContextResolver()
    raw_text = "Contact us at support@example.com for help."
    masked = resolver.mask(raw_text)
    
    assert "support@example.com" not in masked
    assert "[[EMAIL_1]]" in masked
    
    unmasked = resolver.unmask(masked)
    assert unmasked == raw_text

def test_context_resolver_ip():
    resolver = ContextResolver()
    raw_text = "Target server is at IP 192.168.1.50."
    masked = resolver.mask(raw_text)
    
    assert "192.168.1.50" not in masked
    assert "[[IP_ADDRESS_1]]" in masked
    
    unmasked = resolver.unmask(masked)
    assert unmasked == raw_text

def test_context_resolver_api_key():
    resolver = ContextResolver()
    raw_text = 'Use token = "xoxb-1234567890-abcdef" for auth.'
    masked = resolver.mask(raw_text)
    
    assert "xoxb-1234567890-abcdef" not in masked
    assert "[[API_KEY_1]]" in masked
    
    unmasked = resolver.unmask(masked)
    assert unmasked == raw_text

def test_context_resolver_multiple():
    resolver = ContextResolver()
    raw_text = 'Developer admin@company.com with token = "supersecretkey123456" accessed IP 10.0.0.1.'
    masked = resolver.mask(raw_text)
    
    assert "admin@company.com" not in masked
    assert "supersecretkey123456" not in masked
    assert "10.0.0.1" not in masked
    
    assert "[[EMAIL_1]]" in masked
    assert "[[API_KEY_1]]" in masked
    assert "[[IP_ADDRESS_1]]" in masked
    
    unmasked = resolver.unmask(masked)
    assert unmasked == raw_text

def test_policy_server_structural_gating():
    server = PolicyServer()
    
    # search_agent is allowed to query_spanner_graph
    assert server.check_structural_gating("search_agent", "query_spanner_graph") is True
    assert server.check_structural_gating("search_agent", "search_vector_db") is True
    
    # search_agent is NOT allowed to execute_sandbox (deny-by-default)
    assert server.check_structural_gating("search_agent", "execute_sandbox") is False
    
    # coding_agent is allowed to execute_sandbox
    assert server.check_structural_gating("coding_agent", "execute_sandbox") is True
    assert server.check_structural_gating("coding_agent", "query_spanner_graph") is False

@pytest.mark.asyncio
async def test_policy_server_semantic_gating_offline():
    server = PolicyServer()
    # Force client to None to verify fallback behavior
    server.client = None
    
    # In offline mode, semantic gating should fallback to True
    is_safe, reason = await server.check_semantic_gating("execute_sandbox", {"command": "ls"})
    assert is_safe is True
    assert "offline" in reason.lower() or "mock" in reason.lower() or "not active" in reason.lower()

@pytest.mark.asyncio
async def test_policy_server_verify_tool_call_flow():
    server = PolicyServer()
    server.client = None # force offline mode
    
    # Allowed tool call
    ok, msg = await server.verify_tool_call("search_agent", "query_spanner_graph", {"query": "SELECT 1"})
    assert ok is True
    assert "approved" in msg.lower()
    
    # Blocked tool call
    ok, msg = await server.verify_tool_call("search_agent", "execute_sandbox", {"command": "rm -rf /"})
    assert ok is False
    assert "violation" in msg.lower()
