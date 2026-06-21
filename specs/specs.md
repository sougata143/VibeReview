# Specification: VibeReview - Production-Ready Graph-Native Continuous Code Auditor

## 1. Project Overview
VibeReview is a "Tier 3" fully custom code review runtime that acts as a continuous, graph-native continuous code auditor [1, 2]. Instead of relying on a single, monolithic agent, this system deploys a distributed multi-agent ADK pipeline operating over a Knowledge Graph to understand complex legacy code structures [2, 3]. It incorporates an active Red/Blue/Green security teaming architecture to detect vulnerabilities, hallucinated dependencies, and logic flaws, autonomously refactoring the codebase while maintaining strict trajectory observability [4, 5].

## 2. Core Architecture & Concepts Demonstrated
- **Tier 3 Multi-Agent ADK Pipeline:** A decomposed sub-agent pipeline consisting of Search, Story, Impact, Task-breakdown, and Coding agents [2].
- **Graph-Native Context:** Ingests code, documentation, and tickets into a graph database (e.g., Spanner Graph) to allow agents to utilize graph traversal (GQL), vector search (ANN), and full-text search [2, 3].
- **Agentic Security Triad (Red/Blue/Green):** Continuous automated defense mechanisms monitoring the agent's behavior and runtime [5-8].
- **Trajectory Observability:** Utilizes OpenTelemetry to log the "Vibe Trajectory" (API calls, tool inputs, and reasoning steps) to ensure the system is auditable and intent drift is measured [9, 10].

## 3. Production-Ready Security Guardrails (The 7 Pillars)
To prevent the "Confused Deputy" problem and protect against repository poisoning, VibeReview implements the following active defense mechanisms [11, 12]:
- **Ephemeral Sandboxing & Egress Governance (Pillar 1):** All generated code is executed within kernel-level, network-isolated sandboxes (e.g., gVisor) that reset completely between runs, and agents are restricted to non-interactive internet access to prevent downloading typosquatted packages [13-15].
- **Context Hygiene & Data Protection (Pillar 2):** A dynamic `ContextResolver` utility runs as middleware to mask Personally Identifiable Information (PII) with generic placeholders (e.g., `[[API_KEY]]`) before the agent processes any repository data, preventing "Context Hallucination" leaks [13, 16, 17].
- **Hybrid Policy Server (Pillar 4):** A runtime LLM firewall intercepts all tool calls before execution using structural gating (deterministic RBAC rules) and semantic gating (a secondary LLM inspecting intent for policy violations) [18].
- **Zero Ambient Authority & Identity (Pillar 5):** Agents authenticate using unique cryptographic identities (SPIFFE IDs) using Just-In-Time (JIT) downscoping, requesting hyper-restricted tokens scoped to exact data sources that expire instantly [19, 20].
- **The Vibe Diff & MFA (Pillar 5):** For high-stakes automated refactoring, an Evaluator Quorum translates the complex execution trace into a plain-English "Vibe Diff" summary, requiring a human engineer to explicitly approve it via Cryptographic Hardware MFA [21, 22].

## 4. Production Evaluation & Verification
- **AI-Generated Test Coverage:** Before attempting any fix, the agent must generate a failing unit test or reproduction command [23]. The fix is only approved when the automated tests pass, ensuring verification before integration [23].
- **Output vs. Trajectory Evaluation:** The system evaluates not just the functional correctness of the final code (Output Eval), but also the sequence of tool calls and intermediate reasoning steps taken to get there (Trajectory Eval) to catch behavioral drift [24, 25].

## 5. Structural Configurations (YAML)
*Note for Antigravity: Use the following YAML definitions for highly nested configurations to maintain token economics and parsing accuracy [26, 27].*

```yaml
vibe_review_system:
  infrastructure:
    knowledge_graph: "Spanner Graph"
    telemetry: "OpenTelemetry"
    sandbox: "gVisor-isolated ephemeral containers"
    
  security_policies:
    hybrid_policy_server:
      structural_gating: "Deny-by-default RBAC for all code-commit tools"
      semantic_gating: "Secondary Gemini-3.1-pro model inspects payload for PII and logic bombs"
    context_hygiene:
      pii_masking_enabled: true
      resolver_pattern: "[[VARIABLE_NAME]]"

  identity_and_access:
    agent_identity: "SPIFFE ID issuance per sub-agent"
    token_strategy: "JIT Downscoping with instant expiry"
    high_stakes_approval: "Cryptographic Hardware MFA + Vibe Diff translation"
  
  adk_sub_agent_pipeline:
    - agent: "Search"
      role: "Explore the graph database"
    - agent: "Story"
      role: "Capture requirements and context"
    - agent: "Impact"
      role: "Predict side-effects of vulnerabilities or proposed changes"
    - agent: "Task-Breakdown"
      role: "Produce atomic units of work"
    - agent: "Coding"
      role: "Execute refactoring and apply fixes"

  security_triad_configuration:
    red_team_attacker:
      role: "Inject 'Adversarial Vibes' and hidden payloads"
      action: "Test if the primary agent hallucinates an insecure solution"
    blue_team_defender:
      role: "Agent Behavioural Analytics (ABA)"
      action: "Monitor Runtime AgBOM and verify semantic context for intent drift"
    green_team_fixer:
      role: "Stateful Quarantine and Auto-Refactoring"
      action: "Revoke tool access on anomaly, freeze agent state, and autonomously rewrite insecure scripts"

  mcp_connections:
    - server_name: "github_mcp"
      type: "Remote A2A Extension"
      purpose: "Continuous PR and commit monitoring"
    - server_name: "graph_db_mcp"
      type: "Local Data Gateway"
      purpose: "Semantic and structural code retrieval"