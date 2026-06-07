"""Detection of SQL injection via dynamic query construction."""
from __future__ import annotations
import ast
from typing import Iterable, List, Optional
from core.rules.base import Rule
from core.severity import Severity
from core.finding import Finding
from core.registry import register


SQL_EXEC_METHODS = {"execute", "executemany", "executescript", "raw"}


@register
class SqlInjectionRule(Rule):
    rule_id = "SAST-SQLI-001"
    title = "SQL injection via dynamic query"
    severity = Severity.HIGH
    cwe = "CWE-89"
    remediation = (
        "Use parameterised queries (placeholders) instead of f-strings, "
        "string concatenation or .format(). Example: "
        "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))."
    )
    node_types = (ast.Call,)

    def inspect(self, node: ast.AST, source_lines: List[str]) -> Iterable[Finding]:
        assert isinstance(node, ast.Call)
        if not isinstance(node.func, ast.Attribute):
            return
        if node.func.attr not in SQL_EXEC_METHODS:
            return
        if not node.args:
            return

        arg = node.args[0]
        reason = self._is_tainted(arg)
        if reason:
            yield self._finding(
                node,
                f"Dynamically constructed SQL query ({reason}). "
                "Parameterise the query to prevent injection.",
                source_lines,
            )

    @staticmethod
    def _is_tainted(arg: ast.AST) -> Optional[str]:
        if isinstance(arg, ast.JoinedStr):
            return "f-string"
        if isinstance(arg, ast.BinOp) and isinstance(arg.op, (ast.Add, ast.Mod)):
            return "string concatenation / %-formatting"
        if (
            isinstance(arg, ast.Call)
            and isinstance(arg.func, ast.Attribute)
            and arg.func.attr == "format"
        ):
            return ".format() call"
        return None
