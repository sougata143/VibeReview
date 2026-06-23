# VibeReview: Production-Ready Graph-Native Continuous Code Auditor

VibeReview is a "Tier 3" distributed multi-agent ADK pipeline operating over a Knowledge Graph to continuously audit repository code structures. Operating in a Zero-Trust environment, it integrates an active Red/Blue/Green security teaming architecture to detect code vulnerabilities, logic bombs, and intent drift, and automatically refactors issues within kernel-isolated sandboxes.

---

## 1. Problem Statement
Continuous code auditing at enterprise scale is exceptionally challenging due to the following reasons:
* **Complex Dependencies & Structural Blind Spots:** Monolithic LLM auditors analyze files in isolation, lacking the context of call graphs, database schemas, and ticket requirements.
* **Reputation & Repository Poisoning (Confused Deputy):** Autonomous agents can be manipulated via adversarial prompt injections to write backdoor exploits or import malicious dependencies.
* **PII & Secrets Leakage:** Agents reading developer logs or databases risk hallucinating and leaking Personally Identifiable Information (PII) or active credentials in prompt trajectories.
* **Intent Drift & Flaky Evals:** As workflows progress, agent trajectories can drift from the user's initial instructions, rendering traditional output-only assertions ineffective.

---

## 2. Solution: VibeReview
VibeReview solves these problems by decoupling orchestrations, context resolution, and active defense:
* **Graph-Native Context:** Incorporates a local Spanner Graph data gateway to allow agents to utilize structural graph traversals (GQL) and vector search (ANN).
* **Tier 3 Multi-Agent Pipeline:** Decomposes the audit flow into 5 specialized sub-agents coordinating via a sequential workflow graph.
* **Active Security Triad (Red/Blue/Green):** Protects the runtime via active injection testing, behavioral anomaly monitoring, and stateful quarantine remediation.
* **Zero-Trust Guardrails (Pillars 1, 2, 4, 5):** Establishes PII masking preprocessors, structural RBAC tool gating, and semantic LLM firewalls.

---

## 3. Architecture

### Multi-Agent ADK Pipeline
VibeReview implements a decomposed sub-agent pipeline utilizing the ADK 2.x Workflow graph:
```
[START] ➔ [Search Agent] ➔ [Story Agent] ➔ [Impact Agent] ➔ [Task-Breakdown Agent] ➔ [Coding Agent]
```
1. **Search Agent:** Queries the Spanner Graph database using GQL and Vector Search tools.
2. **Story Agent:** Fetches epic requirements, parsing requirements and user contexts.
3. **Impact Agent:** Analyzes call graphs and traces code modifications to predict downstream side-effects.
4. **Task-Breakdown Agent:** Partitions findings into atomic tickets and units of work.
5. **Coding Agent:** Generates refactoring edits, runs unit tests, and applies code fixes inside kernel-isolated sandboxes.

### Red/Blue/Green Security Triad
The runtime security is actively monitored by the following security roles:
* **Red Team (Attacker):** Injects adversarial vibes and hidden payloads to test if the primary agents can be compromised.
* **Blue Team (Defender):** Monitors input values and tool parameters for known signatures (e.g. `rm -rf`) to detect anomalies.
* **Green Team (Fixer):** Enforces a stateful quarantine on detection: immediately locks the agent status, revokes all tool access (raises a quarantined state exception), and triggers auto-refactoring/remediation.

### Model Context Protocol (MCP) Server Connections
VibeReview integrates local stdio-based subprocess connections to external systems:
* **Spanner Graph MCP (`graph_db_mcp`):** Connects to Spanner Graph for structural code retrieval and semantic vector lookups.
* **GitHub MCP (`github_mcp`):** Connects to repository pull requests and commits to monitor incoming PRs.

### Generative UI & Hybrid Output Pattern (A2UI)
VibeReview integrates the **Agent-to-User Interface (A2UI)** framework via the `a2ui-agent-sdk` to securely decouple raw backend data processing from user interface layouts:

* **Declarative 'Sheet Music':** To prevent the LLMs from outputting arbitrary, untrusted frontend scripts or raw HTML, our sub-agents (`Impact Agent` and `Coding Agent`) utilize a shared `A2uiSchemaManager` loaded with a pre-approved `BasicCatalog` (version 0.9). The agents write declarative layout instructions—"sheet music"—specifying pre-approved component primitives (such as `Card`, `List`, `Text`, and `Button`).
* **Hybrid Response Schema:** The final agent output is formatted under a strict three-key JSON envelope (`HybridResponse`):
  1. `data`: Contains raw auditing findings, metrics, and security scan logs.
  2. `ui`: Contains A2UI-compliant version `v0.9` component catalogs detailing how the dashboard should render.
  3. `ui_available`: A boolean flag signaling whether UI layout maps are bundled.
* **Dual Execution Modes:** This hybrid architecture enables VibeReview to operate simultaneously in two distinct environments:
  * **Headless CI/CD Mode:** Headless automated pipelines parse the payload, ignore the `ui` field entirely, and extract raw metrics from the `data` block to grade security checks or write GitHub PR summaries.
  * **Interactive Canvas Mode:** Visual clients (such as the interactive browser Playground or enterprise dashboards) read the `ui` block and reconstruct a rich, dynamic dashboard canvas showing audit results in real-time.

### Architecture Diagram

```mermaid
graph LR
    subgraph Inputs
        KG["Knowledge Graph<br/>code, docs, tickets, other DBs"]
        CC["Code Context<br/>PR diffs, comments, main"]
    end
    
    subgraph Sub-Agent Pipeline
        S[Search] --> I[Impact] --> T[Tasks] --> C[Coding]
    end
    
    KG -- GQL, ANN, text --> S
    CC --> S
```
```mermaid
graph TD
    subgraph ADL ["Active Defense Layer"]
        ID["Agentic Identity"]
        VD["The Vibe Diff - MFA"]
        RBG["Red, Blue, and Green Teaming"]
    end
    
    subgraph CEW ["Code & Execution Workflow"]
        NIA["Non-Interactive Access"]
        SM["State Management"]
        SIL["Shift Left IDE Linters"]
        SB["Ephemeral Sandboxing"] --- NIA
        EG["Egress Governance"] --- NIA
        HPB["Hallucinated Package Blockers"] --- SIL
        MS["MCP Spoofing Defense"]
    end
    
    subgraph ASP ["Agent Security Pillars"]
        P1["1. Infrastructure"]
        P2["2. Data"]
        P3["3. Model"]
        P4["4. App & Runtime"]
        P5["5. IAM"]
        P6["6. Observability & SecOps"]
        P7["7. Governance"]
    end

    ADL -.-> CEW
    CEW -.-> ASP
```

```mermaid
graph TD
    subgraph Agent Harness
        LLM((LLM))
        Mem["Session / Memory Store"]
        Orch["Orchestration Logic"]
        Guard["Guardrails & Hooks"]
        Tools["Tools & MCP Servers"]
        Obs["Observability & Tracing"]
    end

    LLM --- Mem
    LLM --- Orch
    LLM --- Guard
    LLM --- Tools
    LLM --- Obs
    
    Tools -- MCP Transport --> SG[("Spanner Graph Database")]
    Tools -- MCP Transport --> GH["GitHub API"]
```

```mermaid
graph TD
    subgraph Developer Zone
        Dev((Developer)) --> Specs["Define Specs"]
        Specs --> Guardrails["Design Guardrails"]
        Guardrails --> Review["Review & Approve"]
    end
    
    subgraph Agent Factory Floor
        Specs -.-> Plan["Planning Agent"]
        Plan --> Code["Coding Agent"]
        Code --> Test{"Tests & Verification"}
        Test -- Fail: Feedback Loop --> Plan
        Test -- Pass --> Out["Verified Output"]
    end
```

---

## 4. Setup & Running Instructions

Follow these step-by-step instructions to clone the repository, configure the environment, and run verification tools locally.

### Prerequisites
* **Python:** Version 3.11 or higher.
* **uv:** Fast Python package manager (Recommended). Install via:
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
* **Headless CLI / CI-CD Pipeline (`run_standalone.py`):** Runs the pipeline, extracts the raw metrics from the `data` envelope (ignoring the `ui` details), prints the results to standard output, and generates a GitHub PR summary report `pr_security_report.md`.
  ```bash
  .venv/bin/python run_standalone.py
  ```
* **Interactive Canvas UI Client (`run_canvas_ui.py`):** Runs the pipeline, verifies if `ui_available` is true, extracts the declarative layout components from the `ui` block (ignoring the `data` details), and reconstructs a text-based representation of the dashboard layout.
  ```bash
  .venv/bin/python run_canvas_ui.py
  ```


---

## 5. Assets

### Cover Page Banner
![VibeReview Cover Banner](assets/cover_page_banner.png)

### Agentic Workflow Diagram
![VibeReview Agentic Workflow Diagram](assets/architecture_diagram.png)
