# app/sandbox_gating.py
# Dynamic Sandbox Gating logic.
# Performs Linting, AST Mapping, and static Taint Tracking on Python files before sandbox runs.

import ast
import re
from typing import List

class GatingVisitor(ast.NodeVisitor):
    def __init__(self):
        self.errors = []
        self.sources = set()  # variables holding untrusted input
        self.sanitized = set()  # variables holding sanitized/validated data

    def visit_Assign(self, node: ast.Assign):
        # Identify sources and sanitizers on the RHS
        is_source = False
        is_sanitized = False

        if isinstance(node.value, ast.Call):
            func_name = self._get_func_name(node.value.func)
            if func_name in ["input", "raw_input"]:
                is_source = True
            elif func_name in ["int", "float", "escape", "sanitize", "mask_pii"]:
                is_sanitized = True
            elif func_name == "open":
                is_source = True
        elif isinstance(node.value, ast.Subscript):
            # Check for sys.argv[x]
            if isinstance(node.value.value, ast.Attribute):
                attr = node.value.value
                if isinstance(attr.value, ast.Name) and attr.value.id == "sys" and attr.attr == "argv":
                    is_source = True

        # Propagate taint/sanitization to targets
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id
                if is_source:
                    self.sources.add(var_name)
                elif is_sanitized:
                    self.sanitized.add(var_name)
                    if var_name in self.sources:
                        self.sources.remove(var_name)
                else:
                    # Variable aliasing / assignment propagation
                    if isinstance(node.value, ast.Name) and node.value.id in self.sources:
                        self.sources.add(var_name)
                    elif var_name in self.sources:
                        self.sources.remove(var_name)

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        func_name = self._get_func_name(node.func)

        # 1. AST Mapping Gating: Prohibit insecure builtins
        if func_name in ["eval", "exec"]:
            self.errors.append(f"AST Gating Violation: Use of prohibited function '{func_name}' is blocked.")

        # 2. Dynamic Taint Gating: Check input flowing to execution sinks
        sinks = [
            "subprocess.run", "subprocess.Popen", "subprocess.call",
            "os.system", "os.popen", "exec", "eval"
        ]
        if func_name in sinks:
            for arg in node.args:
                if isinstance(arg, ast.Name):
                    var_name = arg.id
                    if var_name in self.sources and var_name not in self.sanitized:
                        self.errors.append(
                            f"Dynamic Taint Gating Violation: Untrusted input variable '{var_name}' "
                            f"flows to dangerous sink '{func_name}' without sanitization."
                        )

        self.generic_visit(node)

    def _get_func_name(self, node) -> str:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            val = self._get_func_name(node.value)
            return f"{val}.{node.attr}" if val else node.attr
        return ""

class LintVisitor(ast.NodeVisitor):
    def __init__(self):
        self.errors = []

    def visit_ExceptHandler(self, node: ast.ExceptHandler):
        if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
            lineno = getattr(node, "lineno", 0)
            self.errors.append(f"Lint Warning: Empty exception catch block at line {lineno} is discouraged.")
        self.generic_visit(node)

def validate_code(code: str, filename: str = "sandbox_code.py") -> List[str]:
    errors = []

    # 1. Linting & Syntax compiling
    try:
        tree = ast.parse(code, filename=filename)
    except SyntaxError as se:
        return [f"Lint/Syntax Error in {filename}:{se.lineno}: {se.msg}"]

    # Basic style linting (Empty except block check via AST)
    lint_visitor = LintVisitor()
    lint_visitor.visit(tree)
    errors.extend(lint_visitor.errors)

    # 2. AST Mapping & 3. Taint Tracking
    visitor = GatingVisitor()
    visitor.visit(tree)
    errors.extend(visitor.errors)

    return errors
