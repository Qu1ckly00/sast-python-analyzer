"""Top-level AST dispatcher.

The ``SecurityAnalyzer`` walks a Python AST once and routes every visited
node to the rules that subscribed to its node type. The actual detection
logic lives in :mod:`core.rules`. This separation of concerns keeps the
analyzer's hot path branchless and lets new rules be added without
touching the dispatcher.
"""
from __future__ import annotations
import ast
from typing import Dict, List, Optional, Tuple, Type
from core.finding import Finding
from core.rules.base import Rule
from core.registry import registry
import core.rules  # noqa: F401 -- triggers rule auto-registration


class SecurityAnalyzer(ast.NodeVisitor):
    """AST visitor that produces a list of :class:`Finding` objects."""

    def __init__(self, disabled_rules: Optional[List[str]] = None) -> None:
        self._rules: List[Rule] = registry.instances(disabled=disabled_rules)
        self._routing: Dict[Type[ast.AST], List[Rule]] = self._build_routing(self._rules)
        self._source_lines: List[str] = []
        self.findings: List[Finding] = []

    @staticmethod
    def _build_routing(rules: List[Rule]) -> Dict[Type[ast.AST], List[Rule]]:
        table: Dict[Type[ast.AST], List[Rule]] = {}
        for rule in rules:
            for node_type in rule.node_types:
                table.setdefault(node_type, []).append(rule)
        return table

    def analyze(self, source: str, file_path: str = "") -> List[Finding]:
        self._source_lines = source.splitlines()
        self.findings = []
        try:
            tree = ast.parse(source)
        except SyntaxError as exc:
            return [
                Finding(
                    rule_id="SAST-PARSE-ERR",
                    title="Parse error",
                    message=f"Cannot parse source: {exc.msg}",
                    severity=__import__("core.severity", fromlist=["Severity"]).Severity.INFO,
                    line=exc.lineno or 0,
                    file_path=file_path,
                )
            ]
        self.visit(tree)
        for finding in self.findings:
            finding.file_path = file_path
        return self.findings

    # --- Dispatcher hooks ---------------------------------------------------
    def generic_visit(self, node: ast.AST) -> None:
        rules = self._routing.get(type(node))
        if rules:
            for rule in rules:
                self.findings.extend(rule.inspect(node, self._source_lines))
        super().generic_visit(node)

    def visit(self, node: ast.AST) -> None:
        # We override visit() to ensure every node passes through generic_visit
        # without having to enumerate visit_* methods per node type.
        self.generic_visit(node)


# --- Convenience wrappers ---------------------------------------------------
def analyze_source(code: str, file_path: str = "") -> List[Finding]:
    """Analyze raw source code; convenience for unit tests and the web UI."""
    return SecurityAnalyzer().analyze(code, file_path=file_path)


def analyze_file(file_path: str) -> List[Finding]:
    """Read ``file_path`` from disk and analyze it."""
    try:
        with open(file_path, "r", encoding="utf-8") as fh:
            source = fh.read()
    except (OSError, UnicodeDecodeError) as exc:
        from core.severity import Severity
        return [
            Finding(
                rule_id="SAST-IO-ERR",
                title="I/O error",
                message=f"Cannot read file: {exc}",
                severity=Severity.INFO,
                line=0,
                file_path=file_path,
            )
        ]
    return SecurityAnalyzer().analyze(source, file_path=file_path)
