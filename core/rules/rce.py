"""Detection of Remote Code Execution via dangerous Python builtins."""
from __future__ import annotations
import ast
from typing import Iterable, List, Optional
from core.rules.base import Rule
from core.severity import Severity
from core.finding import Finding
from core.registry import register


DANGEROUS_BUILTINS = {"eval", "exec", "compile", "__import__"}


@register
class RemoteCodeExecutionRule(Rule):
    rule_id = "SAST-RCE-001"
    title = "Arbitrary code execution"
    severity = Severity.CRITICAL
    cwe = "CWE-95"
    remediation = (
        "Avoid eval/exec on untrusted input. Use a dispatch dictionary of "
        "callables or ast.literal_eval for safe literal parsing."
    )
    node_types = (ast.Call,)

    def inspect(self, node: ast.AST, source_lines: List[str]) -> Iterable[Finding]:
        assert isinstance(node, ast.Call)
        # Only flag bare-name calls like eval(...), exec(...), compile(...).
        # Method calls such as re.compile() or json.loads() are intentionally
        # skipped: their `compile` attribute is unrelated to Python's builtin.
        if isinstance(node.func, ast.Name) and node.func.id in DANGEROUS_BUILTINS:
            yield self._finding(
                node,
                f"Call to dangerous builtin {node.func.id}() enables arbitrary code execution.",
                source_lines,
            )
