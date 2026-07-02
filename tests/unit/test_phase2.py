# tests/unit/test_phase2.py
import unittest
import asyncio
from app.sandbox_gating import validate_code
from app.tools import approve_vibe_diff_with_mfa
from app.agent_runtime_app import agent_runtime
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization

class TestPhase2(unittest.TestCase):
    def test_egress_governance_allows_whitelisted(self):
        code = """
import requests
res = requests.get("https://nvd.nist.gov/api/v1")
"""
        errors = validate_code(code)
        self.assertEqual(len(errors), 0)

    def test_egress_governance_blocks_unapproved(self):
        code = """
import requests
res = requests.get("https://malicious-site.com/inject")
"""
        errors = validate_code(code)
        self.assertTrue(any("Outbound request to unapproved host" in e for e in errors))

    def test_egress_governance_blocks_dynamic(self):
        # Dynamic variable checks
        code_dynamic = """
import requests
dest = get_url()
res = requests.get(dest)
"""
        errors = validate_code(code_dynamic)
        self.assertTrue(any("Dynamic/variable network destination" in e for e in errors))

    def test_webauthn_signature_verification_success(self):
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()

        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        challenge = "random-challenge-uuid"
        signature = private_key.sign(challenge.encode('utf-8'), ec.ECDSA(hashes.SHA256()))
        signature_hex = signature.hex()

        res = approve_vibe_diff_with_mfa(
            vibe_diff="Refactored SQL Injection",
            challenge=challenge,
            signature_hex=signature_hex,
            public_key_pem=public_key_pem
        )
        self.assertEqual(res["status"], "approved")

    def test_webauthn_signature_verification_rejection(self):
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()

        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        res = approve_vibe_diff_with_mfa(
            vibe_diff="Refactored SQL Injection",
            challenge="correct-challenge",
            signature_hex="deadbeef",
            public_key_pem=public_key_pem
        )
        self.assertEqual(res["status"], "rejected")

    def test_webhook_receiver_processing(self):
        # Mock async_stream_query to run fully offline without GCP requests
        async def mock_async_stream_query(*args, **kwargs):
            yield {"content": {"role": "model", "parts": [{"text": '{"data": {"vulnerabilities_found": false, "raw_output": "Audit clean"}}'}]}}
            
        original_stream = agent_runtime.async_stream_query
        agent_runtime.async_stream_query = mock_async_stream_query
        
        payload = {
            "number": 42,
            "pull_request": {"title": "Fix SQL injection in auth module"},
            "repository": {"clone_url": "https://github.com/vibe/review.git"}
        }
        try:
            res = asyncio.run(agent_runtime.receive_webhook(payload))
            self.assertEqual(res["status"], "success")
            self.assertIn("Webhook processed", res["message"])
        finally:
            agent_runtime.async_stream_query = original_stream

if __name__ == '__main__':
    unittest.main()
