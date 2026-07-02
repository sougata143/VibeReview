# app/app_utils/remediation_feedback.py
# Remediation Feedback Learning (Green Team upgrade, Phase 2).
#
# Captures outcomes of Vibe Diff reviews (accepted/rejected patches) and feeds
# them into a structured JSONL dataset formatted for Gemini Supervised Fine-Tuning (SFT).

import os
import json
import logging
import argparse
from datetime import datetime
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

DEFAULT_DATASET_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "artifacts",
    "remediation_feedback.jsonl"
)


class RemediationFeedbackLoop:
    """Manages the feedback loop for autonomous code remediation."""

    def __init__(self, dataset_path: str = DEFAULT_DATASET_PATH):
        self.dataset_path = dataset_path
        # Ensure the directory exists
        os.makedirs(os.path.dirname(self.dataset_path), exist_ok=True)

    def log_feedback(
        self,
        insecure_code: str,
        error_trace: str,
        proposed_patch: str,
        explanation: str,
        severity: str,
        accepted: bool,
        developer_comment: Optional[str] = None,
        model_used: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Log a remediation feedback instance to the JSONL dataset.

        Formats the entry with full metadata and a pre-packaged Gemini SFT
        compatible format.
        """
        # Reconstruct the system prompt / user prompt structure used in remediation
        from app.app_utils.auto_remediation import _REMEDIATION_PROMPT
        user_prompt = _REMEDIATION_PROMPT.format(
            insecure_code=insecure_code,
            error_trace=error_trace,
        )

        expected_response = {
            "patched_code": proposed_patch,
            "explanation": explanation,
            "severity": severity,
        }

        # Format compatible with Google GenAI / Gemini supervised fine-tuning (SFT)
        sft_format = {
            "contents": [
                {"role": "user", "parts": [{"text": user_prompt}]},
                {"role": "model", "parts": [{"text": json.dumps(expected_response, indent=2)}]}
            ]
        }

        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "insecure_code": insecure_code,
            "error_trace": error_trace,
            "proposed_patch": proposed_patch,
            "explanation": explanation,
            "severity": severity,
            "accepted": accepted,
            "developer_comment": developer_comment or "",
            "model_used": model_used or "unknown",
            "gemini_sft_format": sft_format if accepted else None  # Only train on accepted corrections
        }

        with open(self.dataset_path, "a") as f:
            f.write(json.dumps(entry) + "\n")

        logger.info(
            "Logged feedback outcome (accepted=%s) to %s",
            accepted, self.dataset_path
        )
        return entry


def main():
    """CLI interface for logging Vibe Diff feedback manually or from webhooks/UI."""
    parser = argparse.ArgumentParser(description="Log remediation feedback to fine-tuning dataset.")
    parser.add_argument("--insecure", required=True, help="Original insecure code snippet")
    parser.add_argument("--trace", required=True, help="Error trace or violation report")
    parser.add_argument("--patch", required=True, help="Proposed secure patch")
    parser.add_argument("--explanation", default="", help="Explanation of the fix")
    parser.add_argument("--severity", default="HIGH", help="Violation severity")
    parser.add_argument("--accepted", required=True, type=lambda x: (str(x).lower() in ['true', '1', 'yes']), help="True if patch was accepted")
    parser.add_argument("--comment", default="", help="Optional developer comment")
    parser.add_argument("--model", default="gemini-3.1-flash-lite", help="Model that generated the patch")
    parser.add_argument("--output", default=DEFAULT_DATASET_PATH, help="Path to output JSONL file")

    args = parser.parse_args()

    loop = RemediationFeedbackLoop(dataset_path=args.output)
    loop.log_feedback(
        insecure_code=args.insecure,
        error_trace=args.trace,
        proposed_patch=args.patch,
        explanation=args.explanation,
        severity=args.severity,
        accepted=args.accepted,
        developer_comment=args.comment,
        model_used=args.model,
    )
    print(f"Feedback successfully written to {args.output}")


if __name__ == "__main__":
    main()
