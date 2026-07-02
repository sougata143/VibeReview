# app/app_utils/auto_remediation.py
# Autonomous Remediation Feedback Loop (Green Team upgrade).
#
# When the Blue Team / Sandbox Gating detects a policy violation or AST error,
# this engine invokes MULTIPLE dedicated code-fixing LLMs concurrently,
# scores their proposed patches via a weighted rubric, and returns the
# highest-confidence rewrite as a Vibe Diff for human approval.

import os
import asyncio
import logging
import json
import random
import re
from typing import Optional, List
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


# ──────────────────────────────────────────────────────────────────────────────
# Patch Scoring Rubric
# ──────────────────────────────────────────────────────────────────────────────

class PatchScoringRubric:
    """Evaluates candidate patches against a weighted 4-dimension rubric.

    Dimensions (0.0 – 1.0 each):
        1. **Violation Removal** (weight 0.40): Does the patch eliminate the
           flagged violation patterns from the original code?
        2. **Code Preservation** (weight 0.25): Does the patch preserve
           legitimate business logic lines from the original?
        3. **Explanation Quality** (weight 0.20): Does the explanation
           reference the specific violations and describe each change?
        4. **Severity Accuracy** (weight 0.15): Is the declared severity
           consistent with the violation type?
    """

    WEIGHTS = {
        "violation_removal": 0.40,
        "code_preservation": 0.25,
        "explanation_quality": 0.20,
        "severity_accuracy": 0.15,
    }

    # Known dangerous patterns that should be absent from patched code
    DANGEROUS_PATTERNS = [
        "eval(", "exec(", "os.system(", "os.popen(",
        "subprocess.call(", "subprocess.run(", "subprocess.Popen(",
        "__import__(", "compile(",
    ]

    # Severity keywords expected in different violation traces
    SEVERITY_MAP = {
        "CRITICAL": ["eval", "exec", "rm -rf", "command injection", "sql injection"],
        "HIGH": ["taint", "subprocess", "os.system", "deserialization", "xxe"],
        "MEDIUM": ["egress", "network", "unapproved host", "lint"],
        "LOW": ["style", "naming", "convention", "todo"],
    }

    @classmethod
    def score(
        cls,
        original_code: str,
        patched_code: str,
        explanation: str,
        severity: str,
        error_trace: str,
    ) -> dict:
        """Score a candidate patch across all rubric dimensions.

        Returns:
            A dict with per-dimension scores, weights, total weighted score,
            and a human-readable grade (A/B/C/D/F).
        """
        scores = {
            "violation_removal": cls._score_violation_removal(original_code, patched_code, error_trace),
            "code_preservation": cls._score_code_preservation(original_code, patched_code),
            "explanation_quality": cls._score_explanation(explanation, error_trace),
            "severity_accuracy": cls._score_severity(severity, error_trace),
        }

        total = sum(scores[k] * cls.WEIGHTS[k] for k in scores)
        grade = (
            "A" if total >= 0.85 else
            "B" if total >= 0.70 else
            "C" if total >= 0.55 else
            "D" if total >= 0.40 else "F"
        )

        return {
            "dimensions": scores,
            "weights": cls.WEIGHTS,
            "total_score": round(total, 4),
            "grade": grade,
        }

    @classmethod
    def _score_violation_removal(cls, original: str, patched: str, error_trace: str) -> float:
        """Check if dangerous patterns from the original are removed in the patch."""
        original_lower = original.lower()
        patched_lower = patched.lower()

        # Identify which dangerous patterns were in the original
        present_in_original = [p for p in cls.DANGEROUS_PATTERNS if p.lower() in original_lower]
        if not present_in_original:
            # No known dangerous patterns in original — check if error_trace keywords are addressed
            return 1.0 if patched != original else 0.5

        removed = sum(1 for p in present_in_original if p.lower() not in patched_lower)
        return removed / len(present_in_original)

    @classmethod
    def _score_code_preservation(cls, original: str, patched: str) -> float:
        """Measure how much legitimate code structure is preserved."""
        orig_lines = set(line.strip() for line in original.splitlines() if line.strip() and not line.strip().startswith("#"))
        patch_lines = set(line.strip() for line in patched.splitlines() if line.strip() and not line.strip().startswith("#"))

        if not orig_lines:
            return 1.0

        # Filter out lines that contain dangerous patterns (they SHOULD change)
        safe_orig = {l for l in orig_lines if not any(p.lower() in l.lower() for p in cls.DANGEROUS_PATTERNS)}
        if not safe_orig:
            return 1.0

        preserved = sum(1 for l in safe_orig if l in patch_lines)
        return preserved / len(safe_orig)

    @classmethod
    def _score_explanation(cls, explanation: str, error_trace: str) -> float:
        """Score explanation by checking if it references specific violation keywords."""
        if not explanation or explanation == "No explanation provided.":
            return 0.0

        score = 0.0
        # Award points for length (minimum effort threshold)
        if len(explanation) > 20:
            score += 0.3
        if len(explanation) > 80:
            score += 0.2

        # Award points for referencing violation keywords from the error trace
        trace_keywords = re.findall(r'\b\w{4,}\b', error_trace.lower())
        if trace_keywords:
            matches = sum(1 for kw in trace_keywords if kw in explanation.lower())
            keyword_ratio = min(matches / max(len(trace_keywords), 1), 1.0)
            score += 0.5 * keyword_ratio

        return min(score, 1.0)

    @classmethod
    def _score_severity(cls, severity: str, error_trace: str) -> float:
        """Score whether declared severity aligns with the violation trace."""
        if not severity:
            return 0.0

        trace_lower = error_trace.lower()
        severity_upper = severity.upper()

        # Check if the declared severity has matching keywords in the trace
        expected_keywords = cls.SEVERITY_MAP.get(severity_upper, [])
        if any(kw in trace_lower for kw in expected_keywords):
            return 1.0

        # Check if a different severity would be a better match
        for sev, keywords in cls.SEVERITY_MAP.items():
            if any(kw in trace_lower for kw in keywords):
                # Found a match for a different severity — penalize proportionally
                sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
                if sev in sev_order and severity_upper in sev_order:
                    distance = abs(sev_order.index(sev) - sev_order.index(severity_upper))
                    return max(1.0 - (distance * 0.3), 0.0)

        # No keywords matched at all — give a moderate default
        return 0.5


# ──────────────────────────────────────────────────────────────────────────────
# Auto-Remediation Engine (Multi-Model Fan-Out)
# ──────────────────────────────────────────────────────────────────────────────

class AutoRemediationEngine:
    """Green Team Autonomous Remediation Engine with Multi-Model Fan-Out.

    When a vulnerability is detected, fans out the remediation task concurrently
    to multiple specialized code-fixing models (e.g., a security-hardened
    fine-tune alongside the base model). Each candidate patch is scored via the
    ``PatchScoringRubric`` and the highest-confidence result is returned.
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

        # Configure the model pool for multi-model fan-out.
        # Override via comma-separated env-var REMEDIATION_MODELS.
        # Default: run the same flash-lite model with two different temperature
        # profiles (conservative T=0.1 and exploratory T=0.8) to get diverse patches.
        self._model_pool = self._build_model_pool()

    def _build_model_pool(self) -> List[dict]:
        """Build the pool of model configurations for concurrent fan-out.

        Each entry is a dict with:
            ``model``       – model identifier string
            ``temperature`` – sampling temperature
            ``label``       – human-readable label for logging
        """
        env_models = os.environ.get("REMEDIATION_MODELS", "")
        if env_models:
            # User-defined pool: "model_a,model_b,model_c"
            return [
                {"model": m.strip(), "temperature": 0.3, "label": m.strip()}
                for m in env_models.split(",") if m.strip()
            ]

        # Default: dual-temperature fan-out on the same base model
        base_model = os.environ.get("CODE_FIX_MODEL", Config.DEFAULT_MODEL)
        return [
            {"model": base_model, "temperature": 0.1, "label": f"{base_model} (conservative T=0.1)"},
            {"model": base_model, "temperature": 0.8, "label": f"{base_model} (exploratory T=0.8)"},
        ]

    # ──────────────────────────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────────────────────────

    async def remediate(
        self,
        insecure_code: str,
        error_trace: str,
        context: str = "",
    ) -> dict:
        """Autonomously rewrite flagged code using multi-model fan-out.

        Fans out the remediation prompt to all models in the pool concurrently,
        scores each candidate with the ``PatchScoringRubric``, and returns the
        highest-confidence result as a Vibe Diff payload.

        Args:
            insecure_code: The original Python source that triggered violations.
            error_trace:   The formatted list of violations from ``validate_code``.
            context:       Optional additional context (e.g. filename, PR number).

        Returns:
            A dict with keys:
                ``status``           – "patched" | "failed" | "offline_fallback"
                ``patched_code``     – The rewritten secure code (str)
                ``explanation``      – Human-readable change log (str)
                ``severity``         – Highest violation severity (str)
                ``vibe_diff``        – Unified diff string for the Vibe Diff review UI
                ``original_code``    – The untouched insecure code (str)
                ``context``          – Forwarded context string
                ``scoring``          – Rubric scoring breakdown for the winning patch
                ``candidates_count`` – Total candidates evaluated
                ``winning_model``    – Label of the model that produced the best patch
        """
        if not self._client:
            return self._offline_fallback(insecure_code, error_trace, context)

        # Fan out to all models in the pool concurrently
        tasks = [
            self._call_model(model_cfg, insecure_code, error_trace)
            for model_cfg in self._model_pool
        ]
        candidates = await asyncio.gather(*tasks, return_exceptions=True)

        # Filter out failed candidates
        valid_candidates = []
        for i, result in enumerate(candidates):
            if isinstance(result, Exception):
                logger.warning(
                    "MultiModelRemediation: model '%s' failed: %s",
                    self._model_pool[i]["label"], result,
                )
                continue
            if result is not None:
                valid_candidates.append(result)

        if not valid_candidates:
            logger.error("MultiModelRemediation: all model candidates failed.")
            return self._offline_fallback(insecure_code, error_trace, context)

        # Score each candidate via the rubric and select the winner
        best = None
        best_score = -1.0
        for candidate in valid_candidates:
            scoring = PatchScoringRubric.score(
                original_code=insecure_code,
                patched_code=candidate["patched_code"],
                explanation=candidate["explanation"],
                severity=candidate["severity"],
                error_trace=error_trace,
            )
            candidate["scoring"] = scoring
            if scoring["total_score"] > best_score:
                best_score = scoring["total_score"]
                best = candidate

        logger.info(
            "MultiModelRemediation: selected winner '%s' with score %.4f (grade %s) "
            "from %d candidates.",
            best["model_label"], best_score, best["scoring"]["grade"],
            len(valid_candidates),
        )

        return {
            "status": "patched",
            "patched_code": best["patched_code"],
            "explanation": best["explanation"],
            "severity": best["severity"],
            "vibe_diff": self._build_vibe_diff(insecure_code, best["patched_code"], context),
            "original_code": insecure_code,
            "context": context,
            "scoring": best["scoring"],
            "candidates_count": len(valid_candidates),
            "winning_model": best["model_label"],
        }

    async def _call_model(
        self,
        model_cfg: dict,
        insecure_code: str,
        error_trace: str,
    ) -> Optional[dict]:
        """Call a single model configuration and return the parsed result."""
        prompt = _REMEDIATION_PROMPT.format(
            insecure_code=insecure_code,
            error_trace=error_trace,
        )

        max_retries = 2
        backoff_factor = 2.0

        for attempt in range(max_retries):
            try:
                response = await self._client.models.generate_content_async(
                    model=model_cfg["model"],
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        response_mime_type="application/json",
                        temperature=model_cfg.get("temperature", 0.3),
                    ),
                )
                result = json.loads(response.text.strip())
                return {
                    "patched_code": result.get("patched_code", insecure_code),
                    "explanation": result.get("explanation", "No explanation provided."),
                    "severity": result.get("severity", "HIGH"),
                    "model_label": model_cfg["label"],
                }
            except Exception as exc:
                if attempt < max_retries - 1:
                    wait = (backoff_factor ** attempt) + random.uniform(0, 1)
                    await asyncio.sleep(wait)
                else:
                    raise exc

        return None

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
            "scoring": {"dimensions": {}, "weights": {}, "total_score": 0.0, "grade": "F"},
            "candidates_count": 0,
            "winning_model": "offline_fallback",
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
