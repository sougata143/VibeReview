# YouTube Video Script: VibeReview Capstone Demonstration

**Format**: Visuals (Left Column) | Audio / Script (Right Column)  
**Target Duration**: 5 Minutes (Approx. 600–700 words of spoken script)

---

## Section 1: Problem Statement (0:00 - 0:45)

| Visuals | Audio / Script |
| :--- | :--- |
| **[0:00 - 0:15]**<br>Dynamic Title slide: *VibeReview - Self-Defending Continuous Code Auditing*.<br>Screen recording showing a mock GitHub repository with a warning sign over a pull request. | "Hey everyone! Today, we're showing you **VibeReview**, our capstone project designed to solve one of the hardest challenges in modern software engineering: continuous code auditing at scale." |
| **[0:15 - 0:30]**<br>A graphic showing isolated code files with red lines connecting to nothing. Words on screen: *Blind Spots*, *Context Limits*, *PII Leakage*. | "Traditional security scanners look at files in isolation, completely missing the broader structural context—like database schemas or API relationships. Monolithic AI tools try to help, but they easily hit context window limits and risk leaking secrets or PII in their logs." |
| **[0:30 - 0:45]**<br>Red warning icon flashing. Text on screen: *The Confused Deputy / Repository Poisoning* | "Worst of all is the 'Confused Deputy' problem. If an attacker injects a malicious prompt into a ticket or code comment, a naive AI assistant can be tricked into writing backdoors, injecting malicious commands, or importing compromised dependencies. This is where VibeReview steps in." |

---

## Section 2: Why Agents? (0:45 - 1:30)

| Visuals | Audio / Script |
| :--- | :--- |
| **[0:45 - 1:05]**<br>Split screen: On the left, a traditional static analyzer outputting a long list of static warnings. On the right, VibeReview executing an ADK pipeline step-by-step. | "Traditional software warns you, but it doesn't understand developer intent, and it certainly doesn't write fixes. VibeReview is built on the concept of **autonomous security agents**." |
| **[1:05 - 1:30]**<br>Animation illustrating an agent: *Researching -> Planning -> Sandbox Testing -> Generating Vibe Diff -> Submitting PR*. | "Unlike static scripts, agents can reason about requirements, trace code execution paths, and execute tests. VibeReview doesn't just alert you to vulnerabilities; it safely researches the issue, designs a fix, executes reproduction tests inside a sandbox, and automatically creates a sanitized pull request." |

---

## Section 3: Architecture (1:30 - 2:30)

| Visuals | Audio / Script |
| :--- | :--- |
| **[1:30 - 1:55]**<br>Flow diagram of the **Tier 3 Multi-Agent ADK Pipeline** (Search -> Story -> Impact -> Task-Breakdown -> Coding). | "Let’s break down VibeReview's architecture. Built using the **Google Agent Development Kit (ADK)**, we run a sequential pipeline of five specialized sub-agents: **Search** retrieves files, **Story** parses requirements, **Impact** maps dependencies, **Task-Breakdown** plans the work, and **Coding** applies the fix." |
| **[1:55 - 2:15]**<br>Diagram showing the Search agent querying a database graph. Text: *Model Context Protocol (MCP)*. | "Instead of raw file reads, the pipeline uses the **Model Context Protocol (MCP)**. Our Search agent connects to a local **Spanner Graph** data gateway to traverse repository relationships using GQL. The Coding agent connects to a **GitHub MCP** server using zero-trust token parameters." |
| **[2:15 - 2:30]**<br>Shield icon with three rings labeled **Red Team (Simulated Attack)**, **Blue Team (Behavior Monitoring)**, and **Green Team (Stateful Quarantine)**. | "To protect the runner, we wrap the pipeline in the **Agentic Security Triad**. If a tool call triggers a security anomaly, VibeReview instantly revokes tool access, quarantines the session, and triggers auto-remediation." |

---

## Section 4: Demo (2:30 - 4:00)

| Visuals | Audio / Script |
| :--- | :--- |
| **[2:30 - 2:50]**<br>Screen share of the **Antigravity IDE** showing `test_quarantine.py`. The presenter runs `.venv/bin/pytest tests/unit` in the terminal. The test fails as we simulate a command injection payload. | "Let’s see the system in action inside our Antigravity IDE. We are simulating a Green Team test scenario where an agent is fed a malicious command payload—like `rm -rf /`—as part of an adversarial vibe check." |
| **[2:50 - 3:15]**<br>IDE view changes to `security.py`. Zoom in on the `before_tool_callback` showing the Blue Team interception. | "When the Coding Agent attempts to call a tool with this payload, the Blue Team defender plugin intercepts it before execution. Watch what happens in the logs." |
| **[3:15 - 3:45]**<br>The terminal shows the test execution capturing a `SecurityAnomalyException`. The terminal output shows: `agent_status = QUARANTINED` and `remediation_triggered = True`. | "The anomaly is flagged instantly! The Green Team locks the session state, setting the status to QUARANTINED. All subsequent tool calls are blocked. Simultaneously, the Green Team initiates auto-remediation, generating a sanitized, safe script in place of the malicious payload." |
| **[3:45 - 4:00]**<br>Presenter runs `pytest tests/unit` again, and the quarantine tests show a big green success bar. | "With the auto-remediation and gating active, our security tests pass completely, proving that the runtime is fully protected against malicious prompt injections." |

---

## Section 5: The Build (4:00 - 5:00)

| Visuals | Audio / Script |
| :--- | :--- |
| **[4:00 - 4:20]**<br>Logo wall of technologies used: *Google Cloud Vertex AI*, *Google ADK*, *Model Context Protocol (MCP)*, *pytest*, *gVisor*, *Terraform*. | "To build VibeReview, we used the **Google ADK** for multi-agent workflows and session tracking. We used the **Model Context Protocol** for environments, and verified the entire trajectory using local evaluation datasets in `agents-cli`." |
| **[4:20 - 4:40]**<br>IDE view showing the Terraform files inside the `deployment/` directory, and the `agent_runtime_app.py` entrypoint. | "For deployment, VibeReview is fully scaffolded for **Google Cloud Agent Runtime**. Using the Terraform configurations we generated, the agent runs in isolated, auto-scaling containers, complete with cloud logging and zero ambient authority." |
| **[4:40 - 5:00]**<br>Closing slide with repository link: *github.com/vibe-review/vibe-review*. | "VibeReview brings zero-trust security to autonomous software development. Check out our Kaggle submission and clone the repo to secure your agents today. Thanks for watching!" |
