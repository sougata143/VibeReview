# tests/unit/test_phase3.py
import unittest
import os
import asyncio
from app.app_utils.failure_clustering import run_clustering_on_file, get_text_embedding, kmeans
from app.app_utils.microtransactions import L402PaymentHandler

class TestPhase3(unittest.TestCase):
    def test_text_embedding_dimensions_and_normalization(self):
        text = "Verification error or quota limit"
        vector = get_text_embedding(text, dim=16)
        self.assertEqual(len(vector), 16)

        norm = sum(v*v for v in vector)
        self.assertAlmostEqual(norm, 1.0, places=4)

    def test_kmeans_clustering_functional(self):
        vectors = [
            [1.0, 0.0], [0.9, 0.1],
            [0.0, 1.0], [0.1, 0.9],
            [0.5, 0.5], [0.6, 0.4]
        ]
        assignments, centroids = kmeans(vectors, k=3)
        self.assertEqual(len(assignments), 6)
        self.assertEqual(len(centroids), 3)

        self.assertEqual(assignments[0], assignments[1])
        self.assertEqual(assignments[2], assignments[3])
        self.assertEqual(assignments[4], assignments[5])

    def test_failure_clustering_report_generation(self):
        output_file = "artifacts/test_failure_clusters.md"
        if os.path.exists(output_file):
            os.remove(output_file)

        try:
            clusters = run_clustering_on_file(input_file=None, output_file=output_file)
            self.assertTrue(len(clusters) > 0)
            self.assertTrue(os.path.exists(output_file))

            with open(output_file, "r") as f:
                content = f.read()

            self.assertIn("# Failure Mode Clustering Report", content)
            self.assertIn("Cluster", content)
        finally:
            if os.path.exists(output_file):
                os.remove(output_file)

    def test_l402_header_parsing(self):
        handler = L402PaymentHandler()
        header = 'L402 token="test-macaroon-bytes", invoice="lnbc123invoice"'
        res = handler.parse_402_header(header)
        self.assertEqual(res["token"], "test-macaroon-bytes")
        self.assertEqual(res["invoice"], "lnbc123invoice")

    def test_l402_payment_simulation_preimage(self):
        handler = L402PaymentHandler()
        invoice = "lnbc123invoice"
        preimage = handler.simulate_payment(invoice)
        self.assertEqual(len(preimage), 64)

    def test_l402_payment_retry_flow(self):
        handler = L402PaymentHandler()
        call_count = 0

        async def mock_client_call(url, headers=None):
            nonlocal call_count
            call_count += 1

            if not headers or "Authorization" not in headers:
                return {
                    "status_code": 402,
                    "headers": {
                        "WWW-Authenticate": 'L402 token="mock_macaroon", invoice="mock_invoice"'
                    }
                }

            auth = headers["Authorization"]
            if auth.startswith("L402 mock_macaroon:"):
                preimage = auth.split(":")[1]
                expected_preimage = handler.simulate_payment("mock_invoice")
                if preimage == expected_preimage:
                    return {
                        "status_code": 200,
                        "body": "Success! M2M Microtransaction completed."
                    }
            return {"status_code": 401, "body": "Invalid payment proof"}

        # Run payment retry using asyncio.run
        res = asyncio.run(
            handler.handle_402_retry(mock_client_call, url="https://api.vibereview.com/audit")
        )

        self.assertEqual(res["status_code"], 200)
        self.assertEqual(res["body"], "Success! M2M Microtransaction completed.")
        self.assertEqual(call_count, 2)

    def test_fetch_premium_cve_integration(self):
        from app.sub_agents.search.agent import fetch_premium_cve
        res = fetch_premium_cve("requests")
        self.assertEqual(res["status_code"], 200)
        self.assertEqual(res["cve"], "CVE-2026-PREMIUM-X")
        self.assertIn("Premium Zero-Day vulnerability in requests", res["name"])

if __name__ == '__main__':
    unittest.main()
