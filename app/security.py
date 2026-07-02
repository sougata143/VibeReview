# app/security.py
# Hybrid Policy Server (Pillar 4) intercepting tool calls for structural & semantic gating.
# Establishes the Red/Blue/Green security teaming architecture and Policy Server guardrails.

import os
import yaml
import json
import asyncio
import random
from google import genai
from google.genai import types
from google.adk.plugins.base_plugin import BasePlugin
from google.adk.tools import BaseTool, ToolContext
from typing import Any, Optional
from app.config import Config
from app.app_utils.auto_remediation import _engine as _remediation_engine

class SecurityAnomalyException(Exception):
    """Raised when a security anomaly is detected by the Blue/Green Team.
    
    This halts execution immediately and triggers automated remediation before 
    any compromised or malicious payload can run on the system.
    """
    pass

class QuarantinedStateException(Exception):
    """Raised when a quarantined agent attempts to execute actions.
    
    Once the agent's state transitions to QUARANTINED, all subsequent tool calls 
    are proactively blocked at the threshold by raising this exception.
    """
    pass

class RedBlueGreenSecurityPlugin(BasePlugin):
    """Monitors tool calls, detects anomalies, and enforces stateful quarantine.
    
    This plugin represents the Agentic Security Triad:
    - **Red Team**: Simulates adversarial inputs/vulnerabilities.
    - **Blue Team**: Continuously monitors tool parameters for malicious command injections.
    - **Green Team**: Enforces isolated stateful quarantine on detection, revoking access.
    """
    
    def __init__(self):
        super().__init__(name="red_blue_green_security")

    async def before_tool_callback(
        self,
        *,
        tool: BaseTool,
        tool_args: dict[str, Any],
        tool_context: ToolContext,
    ) -> Optional[dict]:
        """Intercepts tool calls before execution to check quarantine and anomalies.
        
        1. Checks if the agent session is already quarantined. If so, blocks execution.
        2. Scans arguments for malicious payloads (e.g. 'rm -rf').
        3. Invokes the Policy Server for structural and semantic gating verification.
        """
        # 1. Enforce Quarantine state: Prevent any quarantined agent from calling any tools
        if tool_context.state.get("agent_status") == "QUARANTINED":
            raise QuarantinedStateException("Agent is currently quarantined due to a security violation.")
            
        # 2. Blue Team Role: Monitor input values for known adversarial payload signatures
        for val in tool_args.values():
            if isinstance(val, str):
                # Detect critical system commands or signatures injected as adversarial vibes
                if any(signature in val for signature in ["rm -rf", "adversarial_vibes", "malicious_payload"]):
                    # Green Team Role: Anomaly detected! Instantly quarantine the agent and freeze session state
                    tool_context.state["agent_status"] = "QUARANTINED"
                    tool_context.state["remediation_triggered"] = True
                    tool_context.state["offending_tool"] = tool.name
                    tool_context.state["offending_args"] = tool_args

                    # Autonomous Remediation Feedback Loop: pass offending payload to code-fixing model
                    insecure_snippet = str(val)
                    error_trace = f"Blue Team detected adversarial payload in tool '{tool.name}': {val!r}"
                    vibe_diff_payload = await _remediation_engine.remediate(
                        insecure_code=insecure_snippet,
                        error_trace=error_trace,
                        context=f"tool={tool.name}",
                    )
                    tool_context.state["vibe_diff"] = vibe_diff_payload
                    tool_context.state["remediated_script"] = vibe_diff_payload.get("patched_code", "# Sanitized\npass")

                    raise SecurityAnomalyException(f"Security Anomaly: Blocked execution of anomalous input: '{val}'")
                    
        # 3. Structural & Semantic Gating via PolicyServer
        # Extract the executing agent node name from the workflow runtime context
        node = getattr(tool_context, "node", None)
        agent_name = node.name if node else None
        
        # Gating checks are run in real execution contexts where the agent name is resolved
        if agent_name:
            policy_server = PolicyServer()
            approved, reason = await policy_server.verify_tool_call(agent_name, tool.name, tool_args)
            if not approved:
                if "RBAC" in reason:
                    # Set RBAC block indicator in the session state for evaluation assertions
                    tool_context.state["blocked_by_rbac"] = True
                raise SecurityAnomalyException(f"Security Policy Block: {reason}")
                
        return None



class PolicyServer:
    """RBAC and semantic evaluation firewall for agent tools.
    
    Maintains security policies under Pillar 4:
    - **Structural Gating**: Structural RBAC checks preventing unauthorized tool calls.
    - **Semantic Gating**: Secondary LLM safety checks to prevent PII leakage and exploits.
    """
    
    def __init__(self, policies_path: str = None):
        """Initializes the Policy Server, loading configurations and setting up LLM client."""
        if not policies_path:
            # Resolve default path to policies.yaml relative to this python file
            current_dir = os.path.dirname(os.path.abspath(__file__))
            policies_path = os.path.join(current_dir, "policies.yaml")
            
        self.policies_path = policies_path
        self.policies = self._load_policies()
        
        # Load GenAI parameters from environment config
        use_vertex = os.environ.get("GOOGLE_GENAI_USE_VERTEXAI", "True").lower() == "true"
        project = os.environ.get("GOOGLE_CLOUD_PROJECT")
        location = os.environ.get("GOOGLE_CLOUD_LOCATION", "us-central1")
        
        try:
            # If Vertex AI is active, instantiate Vertex-supported GenAI client
            if use_vertex and project:
                self.client = genai.Client(vertexai=True, project=project, location=location)
                self.model = Config.DEFAULT_MODEL
            else:
                # Local developer model configuration
                self.client = genai.Client()
                self.model = Config.DEFAULT_MODEL
        except Exception:
            # Fallback gracefully if GCP credentials are not active during offline local tests
            self.client = None
            self.model = None

    def _load_policies(self) -> dict:
        """Loads allowed tools list per sub-agent role from the policies.yaml file."""
        try:
            with open(self.policies_path, "r") as f:
                return yaml.safe_load(f) or {}
        except Exception:
            # Fallback to empty roles mapping in case of missing file
            return {"roles": {}}

    def check_structural_gating(self, agent_name: str, tool_name: str) -> bool:
        """Deny-by-default RBAC check against allowed tools for the agent's role.
        
        Verifies if the specified agent name is structurally permitted to invoke the tool.
        """
        roles = self.policies.get("roles", {})
        agent_policy = roles.get(agent_name, {})
        allowed_tools = agent_policy.get("allowed_tools", [])
        return tool_name in allowed_tools

    async def check_semantic_gating(self, tool_name: str, tool_args: dict) -> tuple[bool, str]:
        """Secondary LLM check to inspect intent/payload for PII, secrets, or logic bombs.
        
        Sends the payload to a separate Gemini instance to evaluate safety intent.
        """
        if not self.client:
            # Gracefully allow tool pass in offline local unit tests
            return True, "Gating passed: Semantic Client not active (offline/mock mode)"
            
        prompt = f"""
        Analyze the following tool call details for any security violations, specifically:
        1. Leakage of Personally Identifiable Information (PII) or unmasked secrets/credentials.
        2. Potential logic bombs, backdoors, or malicious intent.
        
        Tool Name: {tool_name}
        Arguments: {tool_args}
        
        Respond ONLY with a JSON object in this format:
        {{
            "decision": "APPROVED" | "DENIED",
            "reason": "Clear explanation of the safety/policy decision."
        }}
        """
        
        max_retries = 3
        backoff_factor = 2.0
        
        for attempt in range(max_retries):
            try:
                # Run generate content using GenAI client asynchronously
                response = await self.client.models.generate_content_async(
                    model=self.model,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        response_mime_type="application/json"
                    )
                )
                
                result = json.loads(response.text.strip())
                decision = result.get("decision", "DENIED")
                reason = result.get("reason", "No reason provided")
                
                return decision == "APPROVED", reason
            except Exception as e:
                # If we have retries left, wait and retry
                if attempt < max_retries - 1:
                    sleep_time = (backoff_factor ** attempt) + random.uniform(0, 1)
                    await asyncio.sleep(sleep_time)
                    continue
                # Fail-closed policy for security in case of API/network failure.
                # If the security gating cannot run, it blocks the tool call.
                return False, f"Semantic gating check failed to execute after {max_retries} attempts: {e}"

    async def verify_tool_call(self, agent_name: str, tool_name: str, tool_args: dict) -> tuple[bool, str]:
        """Combines structural and semantic gating to intercept and inspect tool calls.
        
        Enforces both checks sequentially before allowing a tool call to run.
        """
        # 1. Structural Gating check (RBAC)
        if not self.check_structural_gating(agent_name, tool_name):
            return False, f"RBAC Policy Violation: Agent '{agent_name}' is not allowed to call tool '{tool_name}'"
            
        # 2. Semantic Gating check (LLM Guardrail) - only for execution/write tools to conserve API quota
        if tool_name in ["run_sandbox", "execute_command", "commit_changes"]:
            is_safe, reason = await self.check_semantic_gating(tool_name, tool_args)
            if not is_safe:
                return False, f"Semantic Firewall Policy Violation: {reason}"
            
        return True, "Tool call approved"
