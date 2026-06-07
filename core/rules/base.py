"""Abstract rule definition.

Each concrete detector (RCE, SQLi, etc.) subclasses ``Rule`` and overrides
``inspect`` for the AST node types it declares in ``node_types``. The
dispatcher in :mod:`core.analyzer` aggregates registered rules and feeds
each AST node only to the rules that subscribed to that node type. This
eliminates the monolithic if/elif chains that plague naive NodeVisitors.
"""
from __future__ import annotations
import ast
from abc import ABC
from typing import List, Optional, Iterable
from core.finding import Finding
from core.severity import Severity


class Rule(ABC):
    """Base class for a detection rule.

    Class-level attributes describe rule metadata (id, severity, CWE,
    remediation). Subclasses must override them. Self-describing rules
    make the resulting reports actionable: a user sees not only the line
    number but also a concrete remediation advice.
    """
    rule_id: str = ""
    title: str = ""
    severity: Severity = Severity.MEDIUM
    cwe: str = ""
    remediation: str = ""

    # AST node types this rule subscribes to. The dispatcher uses this
    # tuple to route nodes efficiently.
    node_types: tuple = ()

    def __init__(self) -> None:
        if not self.rule_id:
            raise ValueError(f"Rule {self.__class__.__name__} has no rule_id")

    def inspect(self, node: ast.AST, source_lines: List[str]) -> Iterable[Finding]:
        """Override in subclass. Yields zero or more Finding objects."""
        return ()

    def _finding(
        self,
        node: ast.AST,
        message: str,
        source_lines: Optional[List[str]] = None,
        confidence: str = "HIGH",
    ) -> Finding:
        """Helper that constructs a Finding using the rule's metadata."""
        snippet = None
        line = getattr(node, "lineno", 0)
        if source_lines and 0 < line <= len(source_lines):
            snippet = source_lines[line - 1].strip()
        return Finding(
            rule_id=self.rule_id,
            title=self.title,
            message=message,
            severity=self.severity,
            line=line,
            column=getattr(node, "col_offset", 0),
            cwe=self.cwe,
            snippet=snippet,
            confidence=confidence,
            remediation=self.remediation,
        )
