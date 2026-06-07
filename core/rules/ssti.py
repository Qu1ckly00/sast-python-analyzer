"""Detection of Server-Side Template Injection (CWE-1336).

SSTI occurs when an attacker can control the *template source* rather
than just its variables. In Python it manifests in three main shapes:

* ``Template(user_input).render(...)`` for Jinja2 / Mako / Tornado.
* ``Environment.from_string(user_input).render(...)`` for Jinja2.
* ``flask.render_template_string(user_input)`` — already partially
  covered by the XSS rule, but here we flag it as SSTI when the
  argument is dynamically built (much higher severity than XSS).
"""
from __future__ import annotations
import ast
from typing import Iterable, List, Optional
from core.rules.base import Rule
from core.severity import Severity
from core.finding import Finding
from core.registry import register


TEMPLATE_CONSTRUCTORS = {"Template"}
TEMPLATE_FROM_STRING = {"from_string"}


@register
class ServerSideTemplateInjectionRule(Rule):
    rule_id = "SAST-SSTI-001"
    title = "Server-Side Template Injection"
    severity = Severity.CRITICAL
    cwe = "CWE-1336"
    remediation = (
        "Never compile a template from user input. Render fixed template "
        "files and pass user data only as render context variables. If "
        "dynamic content is required, sandbox the environment "
        "(jinja2.sandbox.SandboxedEnvironment) and restrict globals."
    )
    node_types = (ast.Call,)

    def inspect(self, node: ast.AST, source_lines: List[str]) -> Iterable[Finding]:
        assert isinstance(node, ast.Call)
        callee = self._callee_name(node.func)

        if callee in TEMPLATE_CONSTRUCTORS and node.args:
            if self._is_dynamic(node.args[0]):
                yield self._finding(
                    node,
                    "Template() constructed from a dynamic string – SSTI risk.",
                    source_lines,
                )

        elif callee in TEMPLATE_FROM_STRING and node.args:
            if self._is_dynamic(node.args[0]):
                yield self._finding(
                    node,
                    "Environment.from_string() compiled from a dynamic string.",
                    source_lines,
                )
        # NOTE: render_template_string is intentionally delegated to the
        # XSS rule. SSTI and XSS are conceptually adjacent on that sink;
        # we keep one finding per location to avoid double reporting.

    @staticmethod
    def _is_dynamic(arg: ast.AST) -> bool:
        if isinstance(arg, (ast.JoinedStr, ast.BinOp)):
            return True
        if (
            isinstance(arg, ast.Call)
            and isinstance(arg.func, ast.Attribute)
            and arg.func.attr in {"format", "join"}
        ):
            return True
        return False

    @staticmethod
    def _callee_name(func: ast.AST) -> Optional[str]:
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            return func.attr
        return None
