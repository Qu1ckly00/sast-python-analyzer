"""Detection of Server-Side Request Forgery (SSRF) sinks."""
from __future__ import annotations
import ast
from typing import Iterable, List, Optional
from core.rules.base import Rule
from core.severity import Severity
from core.finding import Finding
from core.registry import register


# HTTP client entry points covered by the rule. The detection is
# call-name based, so we flag every popular client library at once.
HTTP_CLIENT_CALLS = {
    "get", "post", "put", "delete", "patch", "head", "options", "request",
    "urlopen", "Request",
}

HTTP_CLIENT_MODULES = {"requests", "httpx", "aiohttp", "urllib", "urllib2"}

REQUEST_TAINT_ATTRS = {
    "args", "form", "values", "json", "data", "GET", "POST", "headers",
}


@register
class ServerSideRequestForgeryRule(Rule):
    rule_id = "SAST-SSRF-001"
    title = "Server-Side Request Forgery"
    severity = Severity.HIGH
    cwe = "CWE-918"
    remediation = (
        "Never forward arbitrary user-controlled URLs. Validate the host "
        "against an allow-list, resolve the DNS name and reject private "
        "or loopback IP ranges, disable HTTP redirects on outbound calls."
    )
    node_types = (ast.Call,)

    def inspect(self, node: ast.AST, source_lines: List[str]) -> Iterable[Finding]:
        assert isinstance(node, ast.Call)
        if not self._looks_like_http_client(node.func):
            return

        if not node.args and not node.keywords:
            return

        target = self._extract_url_arg(node)
        if target is not None and self._is_user_controlled(target):
            yield self._finding(
                node,
                "Outbound HTTP request URL is built from a request "
                "parameter, which may enable SSRF.",
                source_lines,
            )

    @staticmethod
    def _looks_like_http_client(func: ast.AST) -> bool:
        # requests.get(...), httpx.post(...), urllib.request.urlopen(...)
        if isinstance(func, ast.Attribute) and func.attr in HTTP_CLIENT_CALLS:
            owner = func.value
            if isinstance(owner, ast.Name) and owner.id in HTTP_CLIENT_MODULES:
                return True
            if isinstance(owner, ast.Attribute) and owner.attr in HTTP_CLIENT_MODULES:
                return True
        # Bare urlopen / Request imported directly.
        if isinstance(func, ast.Name) and func.id in {"urlopen", "Request"}:
            return True
        return False

    @staticmethod
    def _extract_url_arg(node: ast.Call) -> Optional[ast.AST]:
        if node.args:
            return node.args[0]
        for kw in node.keywords:
            if kw.arg in {"url", "uri"}:
                return kw.value
        return None

    @classmethod
    def _is_user_controlled(cls, node: ast.AST) -> bool:
        # Dynamic string (f-string / concat) is a strong SSRF signal.
        if isinstance(node, (ast.JoinedStr, ast.BinOp)):
            for sub in ast.walk(node):
                if cls._is_request_access(sub):
                    return True
            # Even without explicit request access, a built URL is suspicious.
            return any(cls._is_request_access(s) for s in ast.walk(node))
        return cls._is_request_access(node)

    @staticmethod
    def _is_request_access(node: ast.AST) -> bool:
        if isinstance(node, ast.Attribute) and node.attr in REQUEST_TAINT_ATTRS:
            return isinstance(node.value, ast.Name) and node.value.id == "request"
        if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Attribute):
            return (
                node.value.attr in REQUEST_TAINT_ATTRS
                and isinstance(node.value.value, ast.Name)
                and node.value.value.id == "request"
            )
        return False
