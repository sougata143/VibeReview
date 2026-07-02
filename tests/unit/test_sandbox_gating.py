# tests/unit/test_sandbox_gating.py
import unittest
import os
import shutil
from app.sandbox_gating import validate_code
from app.sub_agents.coding.agent import execute_sandbox
from app.sub_agents.search.agent import query_spanner_graph

class TestSandboxGating(unittest.TestCase):
    def test_lint_syntax_error(self):
        code = "def invalid_syntax(:"
        errors = validate_code(code)
        self.assertTrue(any("Syntax Error" in e for e in errors))

    def test_lint_empty_except(self):
        code = """
def bad_practice():
    try:
        x = 1/0
    except:
        pass
"""
        errors = validate_code(code)
        self.assertTrue(any("Empty exception catch block" in e for e in errors))

    def test_ast_prohibited_builtin_eval(self):
        code = "eval('1 + 1')"
        errors = validate_code(code)
        self.assertTrue(any("Use of prohibited function 'eval' is blocked" in e for e in errors))

    def test_ast_prohibited_builtin_exec(self):
        code = "exec('x = 5')"
        errors = validate_code(code)
        self.assertTrue(any("Use of prohibited function 'exec' is blocked" in e for e in errors))

    def test_taint_gating_violation(self):
        code = """
import subprocess
user_in = input("Enter command: ")
subprocess.run(user_in, shell=True)
"""
        errors = validate_code(code)
        self.assertTrue(any("flows to dangerous sink" in e for e in errors))

    def test_taint_gating_approved_with_sanitizer(self):
        code = """
import subprocess
user_in = input("Enter port: ")
safe_in = int(user_in)
subprocess.run(["ping", "-c", "1", "127.0.0.1"])
"""
        errors = validate_code(code)
        self.assertEqual(len(errors), 0)

    def test_execute_sandbox_gating_block(self):
        test_file = "temp_tainted_script.py"
        code = """
import os
user_data = input("Val: ")
os.system(user_data)
"""
        with open(test_file, "w") as f:
            f.write(code)

        try:
            res = execute_sandbox(f"python {test_file}")
            self.assertEqual(res["status"], "failed_gating")
            self.assertTrue(any("Taint Gating Violation" in e for e in res["gating_errors"]))
        finally:
            if os.path.exists(test_file):
                os.remove(test_file)

    def test_spanner_graph_cross_repo_resolver(self):
        mock_repo_dir = "cloned_repos/mock_sibling_repo"
        os.makedirs(mock_repo_dir, exist_ok=True)

        with open(os.path.join(mock_repo_dir, "utils.py"), "w") as f:
            f.write("""
def calculate_vibe_score():
    return 100
""")

        test_source_file = "temp_import_test.py"
        with open(test_source_file, "w") as f:
            f.write("""
import mock_sibling_repo
from mock_sibling_repo.utils import calculate_vibe_score

def run():
    calculate_vibe_score()
""")

        try:
            res = query_spanner_graph(query="cross-repo call map", search_path=".")
            self.assertEqual(res["status"], "success")

            dependencies = res["cross_repo_dependencies"]
            self.assertTrue(len(dependencies) > 0)

            edge_types = [dep["edge_type"] for dep in dependencies]
            self.assertIn("DEPENDS_ON", edge_types)
            self.assertIn("CALLS", edge_types)
        finally:
            if os.path.exists(test_source_file):
                os.remove(test_source_file)
            if os.path.exists(mock_repo_dir):
                shutil.rmtree(mock_repo_dir)

if __name__ == '__main__':
    unittest.main()
