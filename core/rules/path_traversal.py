"""Detection of Path Traversal vulnerabilities.

Looks for filesystem-touching calls (``open``, ``os.path.join``, ``Path``,
``send_file``, ``send_from_directory``) where any argument is derived from
an HTTP request object. The check is intentionally syntactic: a proper
taint analysis would require an inter-procedural data-flow engine which
is out of scope for an AST-based academic prototype, yet the heuristic
catches the most common misuses without an unreasonable FP rate.
"""
from __future__ import annotations
import ast
from typing import Iterable, List, Optional
from core.rules.base import Rule
from core.severity import Severity
from core.finding import Finding
from core.registry import register


FILESYSTEM_SINKS = {
    "open",
    "send_file",
    "send_from_directory",
    "FileResponse",
    "read_text",
    "read_bytes",
}

# Attribute chains that we treat as HTTP-request taint sources.
TAINT_SOURCES = {
    # Flask
    "args", "form", "values", "json", "files", "cookies", "headers",
    # Django
    "GET", "POST", "FILES", "COOKIES",
}


@register
class PathTraversalRule(Rule):
    rule_id = "SAST-PATH-001"
    title = "Path traversal"
    severity = Severity.HIGH
    cwe = "CWE-22"
    remediation = (
        "Validate that the resolved path stays within an allow-listed "
        "directory: use pathlib.Path(base).resolve() and check that the "
        "user-supplied path .is_relative_to(base). Strip slashes and "
        "'..' segments or use werkzeug.utils.secure_filename()."
    )
    node_types = (ast.Call,)

    def inspect(self, node: ast.AST, source_lines: List[str]) -> Iterable[Finding]:
        assert isinstance(node, ast.Call)
        callee = self._callee_name(node.func)
        if callee not in FILESYSTEM_SINKS and callee != "join":
            return

        # os.path.join is only suspicious when it joins request data.
        if callee == "join" and not self._is_os_path_join(node.func):
            return

        for arg in self._iter_args(node):
            if self._contains_request_taint(arg):
                yield self._finding(
                    node,
                    f"{callee}() receives a path derived from an HTTP "
                    "request, which may allow directory traversal.",
                    source_lines,
                )
                return

    @staticmethod
    def _iter_args(node: ast.Call):
        yield from node.args
        for kw in node.keywords:
            yield kw.value

    @classmethod
    def _contains_request_taint(cls, node: ast.AST) -> bool:
        for sub in ast.walk(node):
            if isinstance(sub, ast.Attribute) and sub.attr in TAINT_SOURCES:
                if cls._is_request_object(sub.value):
                    return True
            if isinstance(sub, ast.Subscript) and isinstance(sub.value, ast.Attribute):
                if sub.value.attr in TAINT_SOURCES and cls._is_request_object(sub.value.value):
                    return True
        return False

    @staticmethod
    def _is_request_object(node: ast.AST) -> bool:
        return isinstance(node, ast.Name) and node.id in {"request", "self"}

    @staticmethod
    def _is_os_path_join(func: ast.AST) -> bool:
        if not isinstance(func, ast.Attribute) or func.attr != "join":
            return False
        owner = func.value
        if isinstance(owner, ast.Attribute) and owner.attr == "path":
            return isinstance(owner.value, ast.Name) and owner.value.id == "os"
        return False

    @staticmethod
    def _callee_name(func: ast.AST) -> Optional[str]:
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            return func.attr
        return None
