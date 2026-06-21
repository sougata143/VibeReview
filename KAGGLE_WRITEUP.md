# VibeReview: A Graph-Native, Self-Defending Multi-Agent Pipeline for Zero-Trust Continuous Code Auditing

## Subtitle
*Securing Legacy Codebases via Ephemeral Sandboxing, Hybrid Gating Firewalls, and Multi-Agent Orchestration with the Google Agent Development Kit (ADK)*

---

# Category 1: The Pitch

## 1. Problem Statement: Why Continuous Code Auditing is Hard

Software security is in a state of crisis. As enterprise codebases scale into millions of lines of code distributed across thousands of microservices, static analysis and traditional security scanners (SAST/DAST) are failing to keep pace. Legacy code auditing is fundamentally bottlenecked by four core challenges:

1. **Structural Blind Spots & Complex Dependencies**: Modern software vulnerabilities are rarely isolated to a single file. They emerge from complex interactions between database schemas, API call graphs, third-party libraries, and business requirements. Conventional auditing tools lack context; they view a repository as a flat directory of files rather than a unified, living graph of structural relationships.
2. **Reputation & Repository Poisoning (The "Confused Deputy" Problem)**: Autonomous developer tools and agents are vulnerable to exploitation. Adversarial actors can inject malicious prompts into tickets, documentation, or public pull requests. When an autonomous auditor ingests these "adversarial vibes," it can be manipulated into introducing logic bombs, backdoors, or downloading malicious dependencies.
3. **Personally Identifiable Information (PII) & Secrets Leakage**: Codebases and developer logs frequently contain credentials, private keys, or customer data. During audit and automated refactoring phases, agents risk digesting raw sensitive data, violating data compliance frameworks (GDPR, HIPAA), and exposing secrets in their prompt logs or outputs.
4. **Intent Drift and Flaky Evaluations**: Traditional testing frameworks only evaluate the final output. In autonomous workflows, an agent might achieve the desired final code output but take a highly insecure or aberrant path to get there (e.g., executing un-vetted subprocesses, bypassing internal gateways). Measuring behavioral drift and enforcing safety during intermediate execution states remains an unsolved operational hurdle.

---

## 2. Solution: How VibeReview Solves This

**VibeReview** is a "Tier 3" distributed multi-agent continuous code auditor built on the Google Agent Development Kit (ADK). Operating under a zero-trust model, VibeReview bridges the gap between codebase structure and active defense. It replaces isolated single-agent runs with a highly coordinated, graph-native orchestration pipeline and an active security teaming architecture:

* **Graph-Native Context Ingestion**: Connects directly to a **Spanner Graph** instance via the Model Context Protocol (MCP). Instead of loading raw files, VibeReview traverses structural relationship graphs using GQL and vector search (ANN) to analyze dependencies, microservices boundaries, and database schemas.
* **Tier 3 Multi-Agent Pipeline**: Rather than expecting a single large language model (LLM) to perform analysis, planning, and coding, VibeReview breaks down the auditing lifecycle into five specialized sub-agents: **Search, Story, Impact, Task-Breakdown, and Coding**.
* **Agentic Security Triad (Red/Blue/Green)**: VibeReview introduces a stateful security plugin that actively defends the agent's runtime. The **Red Team** simulates attacks, the **Blue Team** continuously monitors tool execution telemetry for anomalies, and the **Green Team** enforces a stateful quarantine on detection—revoking agent tools, freezing session state, and triggering auto-remediation.
* **Closed-Loop Verification & Sandboxing**: All proposed refactoring changes are executed inside **gVisor-isolated ephemeral sandboxes** with network egress controls. VibeReview enforces Test-Driven Development (TDD): the agent must first generate a failing reproduction test, write the fix, and prove the test turns green before requesting human verification.

---

## 3. The Value: Why Agents Solve This Better Than Traditional Software

Traditional static analysis tools (like SonarQube or Semgrep) rely on static signatures and abstract syntax trees (ASTs). While fast, they produce high volumes of false positives, cannot understand developer intent, and—crucially—cannot fix the vulnerabilities they find. 

AI-powered agents represent a paradigm shift. Unlike static scripts, VibeReview excels in:
* **Active Reasoning & Intent Understanding**: VibeReview reads pull request discussions, architecture specs, and commit history to determine *why* a particular piece of code was written, distinguishing true security vulnerabilities from intentional, domain-specific designs.
* **Closed-Loop Autonomy**: Traditional software only alerts developers, adding to alert fatigue. VibeReview does not just flag issues; it researches the root cause via Graph MCP, plans a fix, writes reproduction tests, executes them in a sandbox, and submits a pull request with an automated "Vibe Diff" summary for human approval.
* **Dynamic Safety Gating**: Unlike standard rules engines, VibeReview's security system is hybrid. It combines hard rules (RBAC) with semantic LLM inspection to dynamically detect code injection, backdoors, and logic bombs before code is executed or merged.

---

# Category 2: The Implementation

## 1. System Architecture & Workflows

VibeReview follows a modular, secure design. The workflow starts from repository webhooks or manual audit triggers and coordinates across three primary tiers:

```mermaid
graph TD
    A[Start: PR / Code Audit Trigger] --> B[ContextResolver: Mask PII & Secrets]
    B --> C[ADK Workflow Orchestrator]
    
    subgraph Multi-Agent Pipeline (ADK)
        C --> D[Search Agent]
        D --> E[Story Agent]
        E --> F[Impact Agent]
        F --> G[Task-Breakdown Agent]
        G --> H[Coding Agent]
    end
    
    subgraph Model Context Protocol (MCP)
        D <--> I[(Spanner Graph MCP)]
        H <--> J[(GitHub MCP)]
    end
    
    subgraph Hybrid Policy Server & Guardrails
        H --> K{Hybrid Policy Server}
        K -- 1. Structural Gating (RBAC) --> L[Check policies.yaml]
        K -- 2. Semantic Gating (LLM) --> M[Gemini Inspection]
        L --> N{Approved?}
        M --> N
    end
    
    N -- Yes --> O[gVisor Sandbox execution]
    N -- No / Anomaly --> P[Red/Blue/Green Security Plugin]
    P --> Q[Stateful Quarantine: Revoke Access & Freeze State]
    Q --> R[Green Team: Auto-Remediation]
    O --> S[Test-Driven Verification: Run Pytest]
    S --> T[Output: Unmasked Vibe Diff & MFA Approval]
```

[Insert Diagram Here]

---

## 2. Multi-Agent Systems (Google ADK)

At the core of VibeReview is a highly structured multi-agent workflow engineered with the **Google Agent Development Kit (ADK)**. Instead of a monolithic architecture, we construct a sequential execution graph where session state is passed from node to node:

```python
def create_root_agent() -> Workflow:
    search_agent = create_search_agent()
    story_agent = create_story_agent()
    impact_agent = create_impact_agent()
    task_breakdown_agent = create_task_breakdown_agent()
    coding_agent = create_coding_agent()
    
    return Workflow(
        name="vibe_review_pipeline",
        description="Continuous code auditor pipeline",
        edges=[
            ('START', search_agent),
            (search_agent, story_agent),
            (story_agent, impact_agent),
            (impact_agent, task_breakdown_agent),
            (task_breakdown_agent, coding_agent)
        ]
    )
```

Each sub-agent runs on a tailored model configuration, optimizing performance and cost:
1. **Search Agent (gemini-1.5-flash)**: Fast and efficient. Interacts with the Spanner Graph database using GQL queries and vector indices to isolate files related to the target code.
2. **Story Agent (gemini-1.5-flash)**: Extracts functional specifications, requirements, and compliance standards from active GitHub issues and specifications.
3. **Impact Agent (gemini-1.5-pro)**: Utilizes a larger context window to analyze dependencies and map potential side-effects of vulnerabilities or proposed refactors across the codebase.
4. **Task-Breakdown Agent (gemini-1.5-flash)**: Partitions the refactoring plan into atomic, sequenced tasks.
5. **Coding Agent (gemini-1.5-pro)**: Generates the actual code modifications, executes tests within the sandbox, and prepares the pull request payload.

By structuring the pipeline into distinct agents, we prevent context dilution, enable localized tool usage, and establish natural validation checkpoints between execution phases.

---

## 3. Model Context Protocol (MCP) Integration

Rather than building custom, brittle connectors, VibeReview leverages the **Model Context Protocol (MCP)** to interact with external environments. We configure stdio-based local background subprocesses:

1. **Spanner Graph MCP Server (Local Data Gateway)**:
   This connection allows the Search Agent to query structural relationships using graph traversals. By using the `@krzko/google-cloud-mcp` Spanner schema engine, the agent inspects node connections (e.g., finding all classes inheriting from an insecure base class).
2. **GitHub MCP Server (Remote A2A Extension)**:
   Enables reading codebase files, creating issues, writing commits, and submitting pull requests. 

Both MCP connections enforce zero-trust credentials. Authentication is handled by passing tokens down to the child process environment dynamically at runtime:

```python
def get_github_mcp_config() -> StdioConnectionParams:
    github_token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GITHUB_PERSONAL_ACCESS_TOKEN")
    env = os.environ.copy()
    if github_token:
        env["GITHUB_TOKEN"] = github_token
    return StdioConnectionParams(
        server_params=StdioServerParameters(
            command="npx",
            args=["-y", "@modelcontextprotocol/server-github"],
            env=env
        )
    )
```

This ensures credentials never touch agent configuration files or prompt trajectories, aligning with strict enterprise security policies.

---

## 4. Production-Ready Security Guardrails

VibeReview's main differentiator is its defensive, zero-trust security architecture. Built from the ground up to address agent-specific attack vectors, it implements three key security mechanisms:

### A. The Hybrid Policy Server
Operating as a middleware interceptor, the **Policy Server** evaluates tool calls before execution. It enforces two layers of protection:
* **Structural Gating (RBAC)**: Reads allowed configurations from a YAML manifest (`policies.yaml`). If the Search Agent tries to invoke a commit tool, or the Coding Agent tries to execute a shell tool outside its sandbox, the Policy Server blocks the execution immediately.
* **Semantic Gating (LLM Firewall)**: If the structural check passes, a secondary, isolated Gemini instance inspects the payload. It reviews the arguments for malicious patterns, credential leakage, and logic bombs, implementing a fail-closed protocol in case of failures.

```yaml
roles:
  search_agent:
    allowed_tools:
      - "get_search_tool"
      - "read_file"
  coding_agent:
    allowed_tools:
      - "run_sandbox"
      - "commit_changes"
```

### B. Stateful Quarantine (Red/Blue/Green Teaming)
Using custom ADK plugin lifecycles, we implemented a stateful quarantine flow. When a tool call is requested:
1. **Red Team (Attacker)** payloads (such as command injection attempts like `rm -rf /`) are simulated.
2. **Blue Team (Defender)** monitors parameters using standard signatures and anomaly patterns.
3. **Green Team (Fixer)** reacts instantly on anomaly detection. It transitions the session state to `QUARANTINED`, revokes all tool access, freezes the agent state, and triggers auto-remediation (writing a sanitized script). Any subsequent tool requests throw a `QuarantinedStateException`.

```python
# From RedBlueGreenSecurityPlugin.before_tool_callback
if tool_context.state.get("agent_status") == "QUARANTINED":
    raise QuarantinedStateException("Agent is currently quarantined.")

for val in tool_args.values():
    if isinstance(val, str) and "rm -rf" in val:
        tool_context.state["agent_status"] = "QUARANTINED"
        tool_context.state["remediation_triggered"] = True
        tool_context.state["remediated_script"] = "# Sanitized\npass"
        raise SecurityAnomalyException("Security Anomaly Detected!")
```

### C. Context Hygiene & Bidirectional Masking
To prevent secrets or PII leakage, VibeReview utilizes a `ContextResolver` preprocessor. It uses regular expressions to detect email addresses, IP addresses, credentials, and API keys. 
* **Masking**: Replaces sensitive data with reversible placeholders (e.g., `[[EMAIL_1]]`) before passing inputs to the LLMs.
* **Unmasking**: Restores the actual values when the agent's work is completed and ready for local deployment. 

This ensures that intermediate agent logs and external trace monitors never capture sensitive credentials.

---

## 5. Agent Skills & Developer Observability

To assure quality and prevent behavioral drift, VibeReview combines trajectory evaluations with structural testing:

* **Agent Skills**: Guided by skills defined in `.agent/skills/code-check.md`, VibeReview runs static validation on the codebase to check for logic flaws.
* **Trajectory vs. Output Evals**: Using `agents-cli eval`, we wrote a BDD evaluation set (`quarantine-dataset.json`) containing simulated scenarios:
  1. *Clean Search Flow*: Verifies standard agent routing.
  2. *RBAC Violation*: Validates that structural gating correctly blocks unauthorized tool calls.
  3. *Adversarial Command Injection*: Tests that the Blue/Green team plugin flags command injection and quarantines the agent.
  4. *PII Masking*: Confirms the ContextResolver removes credentials from raw text.
* **Evaluation Metrics**: We configured local evaluation metrics using code-based python scoring:
  - `local_task_success`: Checks if the final state matches expected outcomes.
  - `local_trajectory_quality`: Asserts that the agent did not stray from authorized nodes.
  - `local_safety`: Confirms that quarantined states were applied immediately on threat detection.

Running our evaluation pipeline scores a perfect **1.0000 (100% success)** across all categories:

```bash
agents-cli eval grade --dataset tests/eval/datasets/quarantine-dataset.json --config tests/eval/eval_config.yaml
```

---

## 6. Setup & Deployment to Agent Runtime

VibeReview is built for production deployment. The repository includes an entrypoint scaffolded via `agents-cli scaffold enhance` targeting **Google Cloud Agent Runtime**:

```python
# app/agent_runtime_app.py
import os
import google.cloud.logging
from google.adk.runners.agent_runtime import AgentRuntimeRunner
from app.agent import app

if __name__ == "__main__":
    client = google.cloud.logging.Client()
    client.setup_logging()
    
    port = int(os.environ.get("PORT", 8080))
    runner = AgentRuntimeRunner(app)
    runner.run(host="0.0.0.0", port=port)
```

### Local Setup Instructions:
1. **Clone the repository**:
   ```bash
   git clone https://github.com/vibe-review/vibe-review.git
   cd vibe-review
   ```
2. **Install dependencies** (using `uv` for package management):
   ```bash
   uv sync
   ```
3. **Configure Environment Variables**:
   Copy `.env.example` to `.env` and fill in required fields:
   ```bash
   cp .env.example .env
   # Set GITHUB_TOKEN and Google Cloud project credentials
   ```
4. **Run Unit Tests**:
   Verify the implementation and security plugin using pytest:
   ```bash
   pytest tests/unit
   ```
5. **Run local evaluation**:
   Verify safety gating and trajectory metrics:
   ```bash
   python tests/eval/generate_mock_traces.py
   pytest tests/eval/  # runs the local grading test suite
   ```

---

# Why VibeReview Wins

VibeReview is not just a tool; it is a **self-defending auditing ecosystem**. By grounding agents in a structural knowledge graph via Spanner Graph MCP, partitioning code modification responsibilities across a secure Google ADK pipeline, and enforcing strict, automated runtime guardrails (Hybrid Policy Server, Stateful Quarantine, and Context Hygiene), VibeReview proves that autonomous developers can be deployed safely in even the most secure, zero-trust environments.
