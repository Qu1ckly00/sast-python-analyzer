"""Detection of XML External Entity (XXE) vulnerabilities (CWE-611).

Python's stdlib XML parsers (``xml.etree``, ``xml.sax``, ``xml.dom``) and
``lxml`` are vulnerable to XXE by default unless explicitly hardened.
The rule flags two patterns:

* Direct calls to ``xml.etree.ElementTree.parse / fromstring``,
  ``xml.sax.parseString``, ``xml.dom.minidom.parse`` etc. when the input
  is dynamic (a user-supplied string / file). Recommendation: switch to
  ``defusedxml``.
* ``lxml.etree.XMLParser`` instantiated with ``resolve_entities=True``
  (the unsafe default) or ``no_network=False``.
"""
from __future__ import annotations
import ast
from typing import Iterable, List, Optional, Tuple
from core.rules.base import Rule
from core.severity import Severity
from core.finding import Finding
from core.registry import register


UNSAFE_XML_PAIRS = {
    ("ElementTree", "parse"),
    ("ElementTree", "fromstring"),
    ("ElementTree", "iterparse"),
    ("etree", "parse"),
    ("etree", "fromstring"),
    ("minidom", "parse"),
    ("minidom", "parseString"),
    ("pulldom", "parse"),
    ("pulldom", "parseString"),
    ("sax", "parse"),
    ("sax", "parseString"),
    ("expatreader", "parse"),
}


@register
class XmlExternalEntityRule(Rule):
    rule_id = "SAST-XXE-001"
    title = "XML External Entity expansion"
    severity = Severity.HIGH
    cwe = "CWE-611"
    remediation = (
        "Replace stdlib XML parsers with the defusedxml package when "
        "parsing untrusted input. For lxml, instantiate XMLParser with "
        "resolve_entities=False and no_network=True."
    )
    node_types = (ast.Call,)

    def inspect(self, node: ast.AST, source_lines: List[str]) -> Iterable[Finding]:
        assert isinstance(node, ast.Call)
        pair = self._module_attr(node.func)

        if pair in UNSAFE_XML_PAIRS:
            module, attr = pair
            yield self._finding(
                node,
                f"{module}.{attr}() from the stdlib does not protect against XXE; "
                "use defusedxml for untrusted XML.",
                source_lines,
                confidence="MEDIUM",
            )
            return

        # lxml.etree.XMLParser(resolve_entities=True) or no_network=False
        callee = self._callee_name(node.func)
        if callee == "XMLParser":
            for kw in node.keywords:
                if kw.arg == "resolve_entities" and self._is_true(kw.value):
                    yield self._finding(
                        node,
                        "lxml XMLParser created with resolve_entities=True; "
                        "external entities will be expanded.",
                        source_lines,
                    )
                    return
                if kw.arg == "no_network" and self._is_false(kw.value):
                    yield self._finding(
                        node,
                        "lxml XMLParser created with no_network=False; "
                        "remote DTDs may be fetched.",
                        source_lines,
                    )
                    return

    @staticmethod
    def _module_attr(func: ast.AST) -> Optional[Tuple[str, str]]:
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            return (func.value.id, func.attr)
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Attribute):
            return (func.value.attr, func.attr)
        return None

    @staticmethod
    def _callee_name(func: ast.AST) -> Optional[str]:
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            return func.attr
        return None

    @staticmethod
    def _is_true(node: ast.AST) -> bool:
        return isinstance(node, ast.Constant) and node.value is True

    @staticmethod
    def _is_false(node: ast.AST) -> bool:
        return isinstance(node, ast.Constant) and node.value is False
