# app/app_utils/auto_remediation.py
# Autonomous Remediation Feedback Loop (Green Team upgrade).
#
# When the Blue Team / Sandbox Gating detects a policy violation or AST error,
# this engine invokes a dedicated code-fixing LLM to rewrite the insecure script
# and stage the patched version as a Vibe Diff for human approval.

import os
import asyncio
import logging
import json
import random
from typing import Optional
from google import genai
from google.genai import types
from app.config import Config

# ──────────────────────────────────────────────────────────────────────────────
# Module-level logger
# ──────────────────────────────────────────────────────────────────────────────
logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Prompt template – stays in sync with the Vibe Diff format
# ──────────────────────────────────────────────────────────────────────────────
_REMEDIATION_PROMPT = """\
You are an expert DevSecOps code-repair agent operating as part of the \
VibeReview Green Team Autonomous Remediation Feedback Loop.

A security or policy violation was detected by the AST Sandbox Gating / Blue Team Monitor.
Your mission is to autonomously rewrite the flagged Python code to eliminate the \
reported violation while preserving all legitimate business logic.

## Violation Report
{error_trace}

## Flagged Code
```python
{insecure_code}
```

## Requirements
1. Remove or replace every pattern that triggered the listed violations.
2. Do NOT introduce new imports unless strictly necessary.
3. Add an inline comment on each changed line explaining the fix.
4. If a taint-flow violation is detected, sanitize the source variable before \
   it reaches the dangerous sink.
5. If an egress violation is detected, replace the disallowed URL/host with a \
   call to the approved allow-listed alternative or raise a clear `ValueError`.

Respond ONLY with a JSON object in the following exact schema:
{{
    "patched_code": "<complete rewritten Python code as a string>",
    "explanation": "<concise explanation of every change made>",
    "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
}}
"""


class AutoRemediationEngine:
    """Green Team Autonomous Remediation Engine.

    Receives flagged code and an error trace from the AST sandbox gating
    pipeline or the Blue Team security plugin, calls a dedicated code-fixing
    Gemini model, and returns a ``VibeDiff`` dict ready for human approval.
    """

    def __init__(self):
        use_vertex = os.environ.get("GOOGLE_GENAI_USE_VERTEXAI", "True").lower() == "true"
        project = os.environ.get("GOOGLE_CLOUD_PROJECT")
        location = os.environ.get("GOOGLE_CLOUD_LOCATION", "us-central1")

        try:
            if use_vertex and project:
                self._client = genai.Client(
                    vertexai=True, project=project, location=location
                )
            else:
                self._client = genai.Client()
        except Exception:
            self._client = None

        # Use the faster flash model as the dedicated code-fixing model.
        # Override via env-var CODE_FIX_MODEL if you want to route to Pro.
        self._model = os.environ.get("CODE_FIX_MODEL", Config.DEFAULT_MODEL)

    # ──────────────────────────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────────────────────────

    async def remediate(
        self,
        insecure_code: str,
        error_trace: str,
        context: str = "",
    ) -> dict:
        """Autonomously rewrite flagged code and return a Vibe Diff payload.

        Args:
            insecure_code: The original Python source that triggered violations.
            error_trace:   The formatted list of violations from ``validate_code``.
            context:       Optional additional context (e.g. filename, PR number).

        Returns:
            A dict with keys:
                ``status``        – "patched" | "failed" | "offline_fallback"
                ``patched_code``  – The rewritten secure code (str)
                ``explanation``   – Human-readable change log (str)
                ``severity``      – Highest violation severity (str)
                ``vibe_diff``     – Unified diff string for the Vibe Diff review UI
                ``original_code`` – The untouched insecure code (str)
                ``context``       – Forwarded context string
        """
        if not self._client:
            return self._offline_fallback(insecure_code, error_trace, context)

        prompt = _REMEDIATION_PROMPT.format(
            insecure_code=insecure_code,
            error_trace=error_trace,
        )

        max_retries = 3
        backoff_factor = 2.0

        for attempt in range(max_retries):
            try:
                response = await self._client.models.generate_content_async(
                    model=self._model,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        response_mime_type="application/json"
                    ),
                )
                result = json.loads(response.text.strip())
                patched = result.get("patched_code", insecure_code)
                explanation = result.get("explanation", "No explanation provided.")
                severity = result.get("severity", "HIGH")

                logger.info(
                    "AutoRemediationEngine: patch generated successfully. "
                    "Severity=%s", severity
                )
                return {
                    "status": "patched",
                    "patched_code": patched,
                    "explanation": explanation,
                    "severity": severity,
                    "vibe_diff": self._build_vibe_diff(insecure_code, patched, context),
                    "original_code": insecure_code,
                    "context": context,
                }
            except Exception as exc:
                if attempt < max_retries - 1:
                    wait = (backoff_factor ** attempt) + random.uniform(0, 1)
                    logger.warning(
                        "AutoRemediationEngine: attempt %d failed (%s). Retrying in %.1fs.",
                        attempt + 1, exc, wait,
                    )
                    await asyncio.sleep(wait)
                else:
                    logger.error(
                        "AutoRemediationEngine: all retries exhausted: %s", exc
                    )

        return self._offline_fallback(insecure_code, error_trace, context)

    # ──────────────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _build_vibe_diff(original: str, patched: str, context: str) -> str:
        """Produces a simple unified-diff-style string for the Vibe Diff UI."""
        original_lines = original.splitlines(keepends=True)
        patched_lines = patched.splitlines(keepends=True)

        diff_lines = [f"--- original  ({context or 'sandbox_code.py'})\n",
                      f"+++ patched   ({context or 'sandbox_code.py'})\n"]
        for line in original_lines:
            diff_lines.append(f"- {line}")
        diff_lines.append("\n")
        for line in patched_lines:
            diff_lines.append(f"+ {line}")

        return "".join(diff_lines)

    @staticmethod
    def _offline_fallback(insecure_code: str, error_trace: str, context: str) -> dict:
        """Deterministic offline fallback used when the GenAI client is unavailable."""
        sanitized = (
            "# Green Team Auto-Remediation (offline fallback)\n"
            "# Original code was quarantined due to the following violations:\n"
            + "".join(f"# {line}\n" for line in error_trace.splitlines())
            + "pass  # Execution blocked pending human review via Vibe Diff\n"
        )
        return {
            "status": "offline_fallback",
            "patched_code": sanitized,
            "explanation": (
                "Offline fallback: GenAI client unavailable. "
                "Code replaced with a safe no-op stub. "
                "Human review required via Vibe Diff."
            ),
            "severity": "HIGH",
            "vibe_diff": AutoRemediationEngine._build_vibe_diff(
                insecure_code, sanitized, context
            ),
            "original_code": insecure_code,
            "context": context,
        }


# ──────────────────────────────────────────────────────────────────────────────
# Module-level singleton for use by security.py and sandbox_gating.py
# ──────────────────────────────────────────────────────────────────────────────
_engine = AutoRemediationEngine()


def request_remediation_sync(
    insecure_code: str,
    error_trace: str,
    context: str = "",
) -> dict:
    """Synchronous convenience wrapper for non-async callers (e.g. sandbox gate).

    Runs the async ``remediate`` coroutine in a thread-safe manner:
    - Uses the running event loop if available.
    - Falls back to ``asyncio.run`` in a fresh loop otherwise.
    """
    async def _run():
        return await _engine.remediate(insecure_code, error_trace, context)

    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=1) as executor:
            return executor.submit(lambda: asyncio.run(_run())).result()
    else:
        return asyncio.run(_run())
