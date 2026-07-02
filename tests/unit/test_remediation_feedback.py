# tests/unit/test_remediation_feedback.py
# Unit tests for the Remediation Feedback Learning system.

import os
import json
import unittest
import tempfile
import subprocess
from app.app_utils.remediation_feedback import RemediationFeedbackLoop


class TestRemediationFeedback(unittest.TestCase):
    """Tests for logging accepted/rejected remediation outcomes to JSONL."""

    def setUp(self):
        # Create a temporary file for the dataset path to isolate tests
        self.temp_dir = tempfile.TemporaryDirectory()
        self.dataset_path = os.path.join(self.temp_dir.name, "remediation_feedback.jsonl")
        self.feedback_loop = RemediationFeedbackLoop(dataset_path=self.dataset_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_log_feedback_accepted(self):
        """Accepted proposed patches should write full metadata and SFT formats to JSONL."""
        insecure = "eval(input_data)"
        trace = "Prohibited function eval"
        patch = "int(input_data)"
        explanation = "Replaced eval with safe typecasting"
        severity = "CRITICAL"
        accepted = True
        comment = "Perfect patch!"
        model = "gemini-3.1-pro-preview"

        # Log feedback
        entry = self.feedback_loop.log_feedback(
            insecure_code=insecure,
            error_trace=trace,
            proposed_patch=patch,
            explanation=explanation,
            severity=severity,
            accepted=accepted,
            developer_comment=comment,
            model_used=model
        )

        # Verify entry returned values
        self.assertEqual(entry["insecure_code"], insecure)
        self.assertEqual(entry["error_trace"], trace)
        self.assertEqual(entry["proposed_patch"], patch)
        self.assertEqual(entry["accepted"], True)
        self.assertIsNotNone(entry["gemini_sft_format"])

        # Check JSONL file content
        self.assertTrue(os.path.exists(self.dataset_path))
        with open(self.dataset_path, "r") as f:
            lines = f.readlines()
            self.assertEqual(len(lines), 1)
            logged_entry = json.loads(lines[0])
            self.assertEqual(logged_entry["accepted"], True)
            self.assertEqual(logged_entry["developer_comment"], comment)
            self.assertIsNotNone(logged_entry["gemini_sft_format"])
            
            # Verify SFT contents
            sft = logged_entry["gemini_sft_format"]
            self.assertIn("contents", sft)
            self.assertEqual(sft["contents"][0]["role"], "user")
            self.assertEqual(sft["contents"][1]["role"], "model")
            self.assertIn(insecure, sft["contents"][0]["parts"][0]["text"])

    def test_log_feedback_rejected(self):
        """Rejected proposed patches should set gemini_sft_format to None to prevent bad learning."""
        insecure = "eval(input_data)"
        trace = "Prohibited function eval"
        patch = "exec(input_data)  # Still dangerous"
        explanation = "Replaced eval with exec"
        severity = "CRITICAL"
        accepted = False
        comment = "This is still insecure!"
        model = "gemini-3.1-flash-lite"

        # Log feedback
        entry = self.feedback_loop.log_feedback(
            insecure_code=insecure,
            error_trace=trace,
            proposed_patch=patch,
            explanation=explanation,
            severity=severity,
            accepted=accepted,
            developer_comment=comment,
            model_used=model
        )

        self.assertEqual(entry["accepted"], False)
        self.assertIsNone(entry["gemini_sft_format"])

        # Check JSONL file content
        with open(self.dataset_path, "r") as f:
            logged_entry = json.loads(f.readlines()[0])
            self.assertEqual(logged_entry["accepted"], False)
            self.assertIsNone(logged_entry["gemini_sft_format"])

    def test_cli_interface(self):
        """Verify the CLI wrapper can log feedback properly via command execution."""
        cmd = [
            ".venv/bin/python",
            "-m",
            "app.app_utils.remediation_feedback",
            "--insecure", "x = eval(y)",
            "--trace", "eval prohibited",
            "--patch", "x = safe_eval(y)",
            "--explanation", "safe eval wrapper",
            "--severity", "HIGH",
            "--accepted", "true",
            "--comment", "LGTM",
            "--model", "test-model",
            "--output", self.dataset_path
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn("Feedback successfully written", result.stdout)

        # Check JSONL file content
        with open(self.dataset_path, "r") as f:
            logged_entry = json.loads(f.readlines()[0])
            self.assertEqual(logged_entry["insecure_code"], "x = eval(y)")
            self.assertEqual(logged_entry["developer_comment"], "LGTM")
            self.assertEqual(logged_entry["model_used"], "test-model")
            self.assertTrue(logged_entry["accepted"])


if __name__ == "__main__":
    unittest.main()
