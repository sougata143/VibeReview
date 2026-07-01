import unittest
from app.context import ContextResolver
from app.security import PolicyServer

class TestSecurity(unittest.TestCase):
    def test_context_resolver_email(self):
        resolver = ContextResolver()
        raw_text = "Contact us at support@example.com for help."
        masked = resolver.mask(raw_text)
        self.assertNotIn("support@example.com", masked)
        self.assertIn("[[EMAIL_1]]", masked)
        self.assertEqual(resolver.unmask(masked), raw_text)

    def test_policy_server_structural_gating(self):
        server = PolicyServer()
        self.assertTrue(server.check_structural_gating("search_agent", "query_spanner_graph"))
        self.assertFalse(server.check_structural_gating("search_agent", "execute_sandbox"))
        self.assertTrue(server.check_structural_gating("coding_agent", "execute_sandbox"))

if __name__ == '__main__':
    unittest.main()
