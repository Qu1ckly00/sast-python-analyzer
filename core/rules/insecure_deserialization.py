"""Detection of insecure deserialization sinks (CWE-502).

Covers ``pickle.loads``/``pickle.load``, ``cPickle``, ``marshal.loads``,
``shelve.open`` and ``yaml.load`` without ``SafeLoader``. Each of these
sinks allows arbitrary object construction on the loading side which
typically degenerates into RCE when the payload is attacker-controlled.
"""
from __future__ import annotations
import ast
from typing import Iterable, List, Optional, Tuple
from core.rules.base import Rule
from core.severity import Severity
from core.finding import Finding
from core.registry import register


# (module, attr) tuples that are inherently unsafe.
UNSAFE_PAIRS = {
    ("pickle", "loads"),
    ("pickle", "load"),
    ("cPickle", "loads"),
    ("cPickle", "load"),
    ("_pickle", "loads"),
    ("_pickle", "load"),
    ("marshal", "loads"),
    ("marshal", "load"),
    ("shelve", "open"),
    ("dill", "loads"),
    ("dill", "load"),
}


@register
class InsecureDeserializationRule(Rule):
    rule_id = "SAST-DESERIAL-001"
    title = "Insecure deserialization"
    severity = Severity.CRITICAL
    cwe = "CWE-502"
    remediation = (
        "Never deserialize data from untrusted sources with pickle/marshal/"
        "shelve. Prefer JSON for data exchange; for YAML always use "
        "yaml.safe_load() (never plain yaml.load() without SafeLoader)."
    )
    node_types = (ast.Call,)

    def inspect(self, node: ast.AST, source_lines: List[str]) -> Iterable[Finding]:
        assert isinstance(node, ast.Call)
        pair = self._module_attr(node.func)
        if pair in UNSAFE_PAIRS:
            module, attr = pair
            yield self._finding(
                node,
                f"{module}.{attr}() deserializes arbitrary data; an "
                "attacker-controlled payload can lead to RCE.",
                source_lines,
            )
            return

        # yaml.load(...) is dangerous unless SafeLoader is explicitly passed.
        if pair == ("yaml", "load") and not self._uses_safe_loader(node):
            yield self._finding(
                node,
                "yaml.load() without SafeLoader is unsafe; use yaml.safe_load() instead.",
                source_lines,
            )

    @staticmethod
    def _module_attr(func: ast.AST) -> Optional[Tuple[str, str]]:
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            return (func.value.id, func.attr)
        return None

    @staticmethod
    def _uses_safe_loader(node: ast.Call) -> bool:
        for kw in node.keywords:
            if kw.arg == "Loader" and isinstance(kw.value, (ast.Name, ast.Attribute)):
                name = kw.value.id if isinstance(kw.value, ast.Name) else kw.value.attr
                if "Safe" in name:
                    return True
        if len(node.args) >= 2:
            loader = node.args[1]
            if isinstance(loader, (ast.Name, ast.Attribute)):
                name = loader.id if isinstance(loader, ast.Name) else loader.attr
                if "Safe" in name:
                    return True
        return False
