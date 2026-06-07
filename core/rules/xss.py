"""Detection of Cross-Site Scripting sinks across popular web frameworks."""
from __future__ import annotations
import ast
from typing import Iterable, List, Optional
from core.rules.base import Rule
from core.severity import Severity
from core.finding import Finding
from core.registry import register


# Sinks that render or trust raw HTML without escaping by default.
XSS_SINKS = {
    "render_template_string",  # Flask: dynamic template body
    "Markup",                  # flask.Markup / markupsafe.Markup: disables escaping
    "HTMLResponse",            # FastAPI / Starlette
}

# Django response classes that do not auto-escape their body.
UNSAFE_HTTP_RESPONSE = {"HttpResponse", "HttpResponseNotFound"}


@register
class CrossSiteScriptingRule(Rule):
    rule_id = "SAST-XSS-001"
    title = "Possible Cross-Site Scripting"
    severity = Severity.HIGH
    cwe = "CWE-79"
    remediation = (
        "Do not return raw HTML built from user input. Rely on the "
        "templating engine's contextual auto-escaping (Jinja autoescape, "
        "Django's escape filter) and never mark user-controlled strings "
        "as 'safe'."
    )
    node_types = (ast.Call, ast.Assign)

    def inspect(self, node: ast.AST, source_lines: List[str]) -> Iterable[Finding]:
        if isinstance(node, ast.Call):
            yield from self._check_call(node, source_lines)
        elif isinstance(node, ast.Assign):
            yield from self._check_autoescape_off(node, source_lines)

    def _check_call(self, node: ast.Call, source_lines: List[str]) -> Iterable[Finding]:
        callee = self._callee_name(node.func)
        if callee in XSS_SINKS:
            yield self._finding(
                node,
                f"Call to {callee}() with possibly untrusted content may "
                "inject HTML/JS into the response.",
                source_lines,
            )
        elif callee in UNSAFE_HTTP_RESPONSE and node.args:
            arg = node.args[0]
            if isinstance(arg, (ast.JoinedStr, ast.BinOp)):
                yield self._finding(
                    node,
                    f"{callee}() with a dynamically built body bypasses auto-escaping.",
                    source_lines,
                    confidence="MEDIUM",
                )
        elif callee == "mark_safe":
            yield self._finding(
                node,
                "mark_safe() disables Django's auto-escaping; the argument "
                "must not contain user input.",
                source_lines,
            )

    def _check_autoescape_off(self, node: ast.Assign, source_lines: List[str]) -> Iterable[Finding]:
        # Flags Jinja2 Environment(autoescape=False) configurations.
        for kw in self._collect_keywords(node.value):
            if kw.arg == "autoescape" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                yield self._finding(
                    node,
                    "Template engine configured with autoescape=False; "
                    "every variable will be rendered unescaped.",
                    source_lines,
                )

    @staticmethod
    def _collect_keywords(value: Optional[ast.AST]) -> List[ast.keyword]:
        if isinstance(value, ast.Call):
            return list(value.keywords)
        return []

    @staticmethod
    def _callee_name(func: ast.AST) -> Optional[str]:
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            return func.attr
        return None
