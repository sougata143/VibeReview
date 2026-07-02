# tests/unit/test_auto_remediation.py
# Unit tests for the Green Team Autonomous Remediation Feedback Loop.

import unittest
import asyncio
from unittest.mock import patch, AsyncMock, MagicMock
from app.app_utils.auto_remediation import AutoRemediationEngine, request_remediation_sync
from app.sandbox_gating import validate_and_remediate


class TestAutoRemediationEngine(unittest.TestCase):
    """Tests for the AutoRemediationEngine offline fallback and Vibe Diff structure."""

    def setUp(self):
        self.engine = AutoRemediationEngine()

    def test_offline_fallback_structure(self):
        """Offline fallback should return all required Vibe Diff keys."""
        result = self.engine._offline_fallback(
            insecure_code="eval(user_input)",
            error_trace="AST Gating Violation: Use of prohibited function 'eval'",
            context="test_file.py",
        )
        self.assertEqual(result["status"], "offline_fallback")
        self.assertIn("patched_code", result)
        self.assertIn("vibe_diff", result)
        self.assertIn("explanation", result)
        self.assertIn("severity", result)
        self.assertEqual(result["original_code"], "eval(user_input)")

    def test_vibe_diff_contains_diff_markers(self):
        """Vibe Diff string should contain unified diff-style markers."""
        diff = self.engine._build_vibe_diff(
            original="eval(x)",
            patched="# patched\npass",
            context="test.py",
        )
        self.assertIn("--- original", diff)
        self.assertIn("+++ patched", diff)
        self.assertIn("- eval(x)", diff)
        self.assertIn("+ # patched", diff)

    def test_offline_fallback_patched_code_is_safe(self):
        """Offline patched code should contain no dangerous eval calls."""
        result = self.engine._offline_fallback(
            insecure_code="exec('rm -rf /')",
            error_trace="Prohibited function exec",
            context="danger.py",
        )
        self.assertNotIn("exec(", result["patched_code"])
        self.assertNotIn("eval(", result["patched_code"])

    def test_remediate_uses_fallback_when_no_client(self):
        """When GenAI client is None, remediate() should return offline_fallback."""
        engine = AutoRemediationEngine()
        engine._client = None   # Force no-client path on the instance
        result = asyncio.run(engine.remediate(
            insecure_code="eval(x)",
            error_trace="Eval prohibited",
        ))
        self.assertEqual(result["status"], "offline_fallback")
        self.assertIn("patched_code", result)

    def test_remediate_sync_wrapper_returns_dict(self):
        """request_remediation_sync should return a dict even with no credentials."""
        result = request_remediation_sync(
            insecure_code="os.system(user_data)",
            error_trace="Taint flow to os.system",
            context="sync_test.py",
        )
        self.assertIsInstance(result, dict)
        self.assertIn("status", result)
        self.assertIn("vibe_diff", result)


class TestValidateAndRemediate(unittest.TestCase):
    """Tests for the validate_and_remediate sandbox gate integration."""

    def test_clean_code_passes_without_remediation(self):
        """Clean code should pass with no errors and no Vibe Diff payload."""
        clean_code = "x = 1 + 2\nprint(x)\n"
        result = validate_and_remediate(clean_code, filename="clean.py")
        self.assertTrue(result["passed"])
        self.assertEqual(result["errors"], [])
        self.assertIsNone(result["vibe_diff"])

    def test_eval_code_fails_and_triggers_remediation(self):
        """Code using eval() should fail gating and return a Vibe Diff payload."""
        insecure_code = "result = eval(user_input)\n"
        result = validate_and_remediate(insecure_code, filename="vuln.py")
        self.assertFalse(result["passed"])
        self.assertTrue(len(result["errors"]) > 0)
        self.assertIsNotNone(result["vibe_diff"])
        vibe_diff = result["vibe_diff"]
        self.assertIn("patched_code", vibe_diff)
        self.assertIn("vibe_diff", vibe_diff)

    def test_taint_flow_triggers_remediation(self):
        """Taint flow from sys.argv to os.system should fail and auto-remediate."""
        tainted_code = (
            "import sys\n"
            "import os\n"
            "cmd = sys.argv[1]\n"
            "os.system(cmd)\n"
        )
        result = validate_and_remediate(tainted_code, filename="tainted.py", context="PR#42")
        self.assertFalse(result["passed"])
        vibe_diff = result["vibe_diff"]
        self.assertEqual(vibe_diff["context"], "PR#42")
        self.assertIn("original_code", vibe_diff)

    def test_remediation_result_has_all_vibe_diff_keys(self):
        """The Vibe Diff payload must expose all keys required by the review UI."""
        code = "x = eval('1+1')\n"
        result = validate_and_remediate(code)
        vd = result["vibe_diff"]
        for key in ["status", "patched_code", "explanation", "severity", "vibe_diff", "original_code"]:
            self.assertIn(key, vd, f"Missing key: {key}")


if __name__ == "__main__":
    unittest.main()
