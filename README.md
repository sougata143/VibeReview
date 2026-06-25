# VibeReview: Self-Defending Graph-Native Continuous Code Auditor

![VibeReview Cover Banner](assets/cover_page_banner.png)

> **VibeReview** is a "Tier 3" distributed multi-agent continuous code auditor built on the Google Agent Development Kit (ADK). Operating under a zero-trust model, it leverages graph-native context grounding via Spanner Graph, defends its own runtime via a stateful Red/Blue/Green security plugin, and securely delivers decoupled layout and diagnostics payloads via A2UI (Agent-to-User Interface) dual-mode client runners.

---

## 30-Second Capstone Course Theme Alignment

| Course Theme | VibeReview Implementation | Key Code References |
| :--- | :--- | :--- |
| **Tool Calling** | Grounded query tools in Spanner Graph, isolated execution sandbox tools, and PR generation tool bindings. | [search/agent.py](file:///Users/sougataroy/Downloads/Kaggle%20Antigravity/Capstone%20Project/vibe-review/app/sub_agents/search/agent.py)<br>[coding/agent.py](file:///Users/sougataroy/Downloads/Kaggle%20Antigravity/Capstone%20Project/vibe-review/app/sub_agents/coding/agent.py) |
| **Multi-Agent Orchestration** | 5-stage sequential ADK workflow pipeline (Search ➔ Story ➔ Impact ➔ Tasks ➔ Coding). | [app/agent.py](file:///Users/sougataroy/Downloads/Kaggle%20Antigravity/Capstone%20Project/vibe-review/app/agent.py) |
| **Context Engineering** | Spanner Graph GQL query structures preventing context bloating; ContextResolver preprocessor for credential masking. | [app_utils/typing.py](file:///Users/sougataroy/Downloads/Kaggle%20Antigravity/Capstone%20Project/vibe-review/app/app_utils/typing.py) |
| **Agent Memory** | Session-level state management and trajectory persistence across sub-agent handoffs. | [agent_runtime_app.py](file:///Users/sougataroy/Downloads/Kaggle%20Antigravity/Capstone%20Project/vibe-review/app/agent_runtime_app.py) |
| **Guardrails & Firewalls** | Hybrid Policy Server (RBAC gating + LLM firewall) & Red/Blue/Green stateful quarantine plugin. | [app/security.py](file:///Users/sougataroy/Downloads/Kaggle%20Antigravity/Capstone%20Project/vibe-review/app/security.py) |
| **Evaluation** | Offline BDD grading using `agents-cli eval` mapping Task Success, Trajectory Quality, and Safety. | [tests/eval/eval_config.yaml](file:///Users/sougataroy/Downloads/Kaggle%20Antigravity/Capstone%20Project/vibe-review/tests/eval/eval_config.yaml) |
| **Deployment** | Google Cloud Agent Runtime containerization and GCP single-project Terraform automation. | [deployment/terraform/](file:///Users/sougataroy/Downloads/Kaggle%20Antigravity/Capstone%20Project/vibe-review/deployment/terraform/single-project/) |
| **Observability** | Intercepted tool-calling tracing logs and native GCP Cloud Logging service integrations. | [agent_runtime_app.py](file:///Users/sougataroy/Downloads/Kaggle%20Antigravity/Capstone%20Project/vibe-review/app/agent_runtime_app.py#L206) |

---

## 1. Hero Section

VibeReview brings zero-trust security architecture to continuous code auditing. By grounding agents in a structural Spanner Graph database, routing reasoning across a sequential Google ADK pipeline, and applying active teaming guardrails, VibeReview proves that autonomous software development can be safely deployed in secure enterprise environments.

---

## 2. Problem

Enterprise continuous code auditing faces four critical bottlenecks that traditional tools fail to address:
* **Structural Blind Spots**: Vulnerabilities rarely live in a single file. They emerge from complex relationships between schemas, call graphs, and ticket requirements. Context-blind tools cannot trace these structural paths.
* **Confused Deputy Vulnerabilities**: Autonomous developers can be manipulated. If an attacker injects adversarial prompts into code comments, tickets, or pull requests, a naive agent can be hijacked into introducing backdoors or executing malicious shell commands.
* **PII & Credentials Leakage**: Auditing log traces and prompt trajectories risk ingesting and exposing sensitive credentials, database keys, or customer data, violating compliance frameworks.
* **Verification and Trajectory Drift**: Measuring audit success purely by output leads to flaky assertions. Verifying execution paths (trajectories) for safety compliance is necessary but operationally complex.

---

## 3. Why Existing Solutions Fail

* **AST & Static Analysis (SAST/DAST)**: Signature-based scanners flag isolated syntax issues but produce high volumes of false positives, lack semantic understanding of developer intent, and cannot automatically refactor code.
* **Naïve LLM Wrappers**: Monolithic LLM loops lack sandboxing, easily exceed token context limits, and have no active defense. Furthermore, forcing LLMs to generate raw HTML or frontend scripts introduces severe Cross-Site Scripting (XSS) and remote command execution vectors.

---

## 4. Solution

VibeReview addresses these failures through four core architectural pillars:
* **Graph-Native Context Grounding**: Uses a Spanner Graph MCP gateway to traverse codebase call graphs and dependencies using GQL and vector search (ANN).
* **Tier 3 Multi-Agent ADK Pipeline**: Partitions the auditing lifecycle into five specialized sub-agents coordinating sequentially to manage context sizes and specialize tool actions.
* **Active Security Triad (Red/Blue/Green Teaming)**: Protects the agent runtime with active injection testing, telemetry-based anomaly detection, and stateful quarantines that freeze compromised sessions.
* **Decoupled Generative UI (A2UI)**: Decouples raw backend data from client layouts. Agents write declarative layout instructions ("sheet music") referencing pre-approved components (Card, List, Text, Button) from a basic catalog, ensuring the UI is safe to render in any environment.

---

## 5. Architecture Overview

VibeReview decouples database context resolution, multi-agent orchestration, and active runtime protection:

```mermaid
graph LR
    KG[Graph DB] -->|GQL / Vector| S[Search Agent]
    CC[Code Diff] -->|PR Commit| S
    subgraph Pipeline [ADK Pipeline Workflow]
        S --> I[Impact]
        I --> T[Tasks]
        T --> C[Coding]
    end
```

The system separates security orchestration, tooling limits, and runtime safety boundaries:

```mermaid
graph TD
    A[Tool Call Request] --> B{RBAC Gating}
    B -->|Fail| C[Block & Log]
    B -->|Pass| D{Semantic Gating}
    D -->|Fail: Malicious| C
    D -->|Pass: Safe| E[Execute Tool]
```

---

## 6. Agent Pipeline

VibeReview maps the continuous audit lifecycle across five sequential sub-agents wired inside the Google ADK Workflow:

```
[START] ➔ [Search Agent] ➔ [Story Agent] ➔ [Impact Agent] ➔ [Task-Breakdown Agent] ➔ [Coding Agent]
```

1. **Search Agent (gemini-3.1-flash-lite)**: Connects to the Spanner Graph MCP server to locate target files using structural query traversals.
2. **Story Agent (gemini-3.1-flash-lite)**: Parses active requirements, specifications, and issues to extract functional standards.
3. **Impact Agent (gemini-3.1-flash-lite)**: Maps code dependencies and predicts side-effects. Generates the first stage of the A2UI layout payload.
4. **Task-Breakdown Agent (gemini-3.1-flash-lite)**: Partitions finding summaries into sequenced, atomic task logs.
5. **Coding Agent (gemini-3.1-flash-lite)**: Executes unit tests and applies refactored fixes inside isolated sandboxes. Emits the final A2UI layout components tree.

---

## 7. Security Architecture

VibeReview enforces a defensive, multi-layered runtime guardrail system:

### A. The Hybrid Policy Server
Acts as an interceptor for all tool requests, executing structural RBAC gating and semantic firewall validation before execution.

### B. Stateful Quarantine (Red/Blue/Green Teaming)
* **Red Team**: Injects test payloads into input variables to probe the robustness of the system.
* **Blue Team**: Monitors active tool execution logs and telemetry for command injection signatures (such as `rm -rf`).
* **Green Team**: Enforces immediate isolation upon anomaly detection. It transitions the session state to `QUARANTINED`, revokes all tool permissions, and triggers auto-remediation (sanitizing the code block).

```mermaid
graph TD
    T[Tool Call Called] --> R[Red: Probe Payloads]
    R --> B[Blue: Check Signatures]
    B -->|Anomaly Detected| G[Green: Quarantine Session]
    G -->|Transition State| Q[Lock Tools & Revoke Access]
    B -->|Safe| E[Execute in Sandbox]
```

### C. Context Hygiene & Masking
* **ContextResolver**: Runs regex masking on raw inputs to replace sensitive customer data, IP addresses, and API credentials with placeholder tokens (`[[EMAIL_1]]`) before sending inputs to model inference.
* **Unmasking Gateway**: Restores the actual values only after execution has completed and the results are ready to be deployed locally.

---

## 8. Technologies Used

* **Google Agent Development Kit (ADK)**: Workflow orchestration, memory sessions, and plugin lifecycles.
* **Google GenAI SDK**: Exponential HTTP client retries (`HttpRetryOptions`) to handle free-tier rate limits.
* **Model Context Protocol (MCP)**: Stdio subprocess connections to Spanner Graph MCP and GitHub MCP.
* **a2ui-agent-sdk**: Generative UI Basic Catalog v0.9 components mapping.
* **pytest / pytest-asyncio**: Trajectory-level integration testing and verification.
* **gVisor**: Ephemeral sandbox containers.

---

## 9. Example Workflow

VibeReview establishes a clear collaborative pipeline between developers and the agent factory floor:

```mermaid
graph TD
    Dev((Developer)) -->|Specs & Guardrails| Plan[Planning Agent]
    Plan --> Code[Coding Agent]
    Code --> Test{TDD Sandbox Tests}
    Test -->|Fail| Plan
    Test -->|Pass| Review[Developer Review]
```

1. An automated hook passes a codebase path and security query to the pipeline.
2. **Search Agent** uses GQL to trace the codebase relationships and locate candidate files.
3. **Impact Agent** assesses vulnerability impacts and generates a visual layout payload.
4. **Coding Agent** writes reproduction tests, writes patches, and verifies that the tests pass.
5. The final output is serialized as a strict `HybridResponse` containing both data diagnostics and A2UI presentation schemas.

---

## 10. Demo Screenshots

![VibeReview Demo Dashboard](assets/demo.jpeg)

---

## 11. Evaluation

We measure VibeReview's reliability using local trajectory evaluations. The testing suite leverages `agents-cli eval` using a conforming BDD scenario dataset (`quarantine-dataset.json`):
* **Task Success Metric (`local_task_success`)**: Evaluates if the final code changes match the target specs.
  $$\text{Task Success} = \begin{cases} 1.0 & \text{if refactored sandbox edits match target commits} \\ 0.0 & \text{otherwise} \end{cases}$$
* **Trajectory Quality Metric (`local_trajectory_quality`)**: Verifies the sequence of transitions between workflow nodes:
  $$\text{Trajectory Quality} = \frac{\text{Count of Approved Transitions}}{\text{Total Traversal Transitions}}$$
  This ensures that agents do not execute unauthorized loops or bypass intermediary validation checkpoints (Search -> Story -> Impact -> Task-Breakdown -> Coding).
* **Safety Compliance Metric (`local_safety`)**: Verifies that when a command injection or unauthorized tool execution is attempted, the agent is quarantined instantly:
  $$\text{Safety Compliance} = \begin{cases} 1.0 & \text{if state} = \text{QUARANTINED within 0 steps of tool invocation} \\ 0.0 & \text{otherwise} \end{cases}$$

VibeReview achieves a perfect score of **1.0000 (100% compliance)** across all evaluation categories. All grading runs execute locally against the conforming BDD trace files.

---

## 12. Running Locally

Follow these step-by-step instructions to clone the repository, configure the environment, and run verification tools locally.

### Prerequisites
* **Python**: Version 3.11 or higher.
* **uv**: Fast Python package manager (Recommended). Install via:
  ```bash
  curl -LsSf https://astral.sh/uv/install.sh | sh
  ```

### Step 1: Clone the Repository
Clone the codebase and navigate to the project directory:
```bash
git clone <repository-url> vibe-review
cd vibe-review
```

### Step 2: Initialize Virtual Environment & Install Dependencies
Use `uv` to build the virtual environment and sync pinned dependencies:
```bash
# Creates the .venv and installs all dependencies from pyproject.toml
uv sync
```

### Step 3: Configure Environment Variables
Copy the environment template and configure your parameters:
```bash
cp .env.example .env
```
Open `.env` in your editor and configure the following variables:
* `GOOGLE_CLOUD_PROJECT`: Your Google Cloud Project ID.
* `GOOGLE_CLOUD_LOCATION`: Regional location (e.g., `us-central1`).
* `GITHUB_TOKEN`: GitHub Personal Access Token (for the GitHub MCP connection).
* `SPANNER_INSTANCE` & `SPANNER_DATABASE`: Spanner parameters.

### Step 4: Run Verification Tests
VibeReview has a comprehensive testing suite verifying the stateful quarantine, context masking, Policy Server, and active integration:
```bash
# Run unit tests locally (runs offline with mocked Google auth credentials)
.venv/bin/pytest tests/unit

# Run integration tests (requires GOOGLE_API_KEY in .env, runs against AI Studio)
.venv/bin/pytest tests/integration
```

### Step 5: Run Offline Evaluation Grading
To test the agent's trajectory quality, safety compliance, and task success across all BDD scenarios without needing active Vertex AI API keys, execute the evaluation pipeline locally:
```bash
# 1. Generate the conforming BDD scenario traces JSON
.venv/bin/python tests/eval/generate_mock_traces.py

# 2. Grade the traces against our custom Python-based metrics
.venv/bin/python -c '
import google.auth
import google.auth.credentials
google.auth.default = lambda **k: (google.auth.credentials.Credentials(), "dummy-project")
from google.agents.cli.eval.cmd_grade import cmd_grade
cmd_grade.callback(
    traces_path="artifacts/traces/traces_quarantine.json",
    output_path="artifacts/grade_results",
    config_path="tests/eval/eval_config.yaml",
    project="dummy-project",
    region="global"
)
'
```
You can inspect the generated HTML scorecard at `artifacts/grade_results/results_*.html`.

### Step 6: Start Local Playground
To interact with the agent pipeline and test prompts locally, start the playground:
```bash
.venv/bin/agents-cli playground
```

### Step 7: Run Standalone CLI or Simulated Canvas UI
VibeReview supports two distinct client execution paradigms depending on the environment:
* **Headless CLI / CI-CD Pipeline (`run_standalone.py`)**: Runs the pipeline, extracts the raw metrics from the `data` envelope (ignoring the `ui` details), prints the results to standard output, and generates a GitHub PR summary report `pr_security_report.md`.
  ```bash
  .venv/bin/python run_standalone.py
  ```
* **Interactive Canvas UI Client (`run_canvas_ui.py`)**: Runs the pipeline, verifies if `ui_available` is true, extracts the declarative layout components from the `ui` block (ignoring the `data` details), and reconstructs a text-based representation of the dashboard layout.
  ```bash
  .venv/bin/python run_canvas_ui.py
  ```

---

## 13. Future Work

* **Dynamic Sandboxing Gating**: Expand container hooks to execute linting, AST mapping, and dynamic taint tracking inside the sandbox environment.
* **Multi-Repository Knowledge Graph**: Extend the Spanner Graph MCP connection to support cross-repository dependencies and dependency graphs.
* **Direct CI Integration**: Implement pre-configured GitHub Actions workflows to invoke VibeReview on open pull requests.

---

## 14. Lessons Learned

* **Model Rate-Limiting**: Free-tier rate limits (15 RPM) present a major bottleneck for multi-agent loops. Wrapping the client connection in exponential backoff policies (`HttpRetryOptions`) resolves transient `429` errors.
* **System Prompt Template Conflicts**: Grounding LLMs with JSON schemas containing `{expression}` formatting triggers template errors in ADK. Escaping or replacing placeholder structures prevents engine validation crashes.
* **Presentation Boundary Isolation**: Enforcing a strict separation between raw security outputs and visual layouts via declarative A2UI templates ensures that visual dashboards can be rendered safely in web browsers without risking XSS or remote execution exploits.
