"""Detection of hardcoded secrets and credentials.

The rule combines two complementary heuristics:

1. Name-based: the assignment target name contains a sensitive keyword
   (password, token, api_key, ...). Cheap, low FP for clearly named
   secrets, but misses cryptic variable names.

2. Shannon-entropy based: the literal value has high entropy and is
   long enough to plausibly be a real credential. This is the same
   approach used by tools like TruffleHog and detect-secrets to surface
   tokens hidden under non-obvious identifiers.
"""
from __future__ import annotations
import ast
import math
import re
from collections import Counter
from typing import Iterable, List
from core.rules.base import Rule
from core.severity import Severity
from core.finding import Finding
from core.registry import register


SECRET_NAME_KEYWORDS = (
    "password", "passwd", "pwd",
    "secret", "api_key", "apikey",
    "token", "access_key", "private_key",
    "auth", "credential",
)

# Patterns that look like obvious placeholders – suppress to reduce FPs.
PLACEHOLDER_PATTERNS = (
    re.compile(r"^(?:\*+|x+|\.+|<.+>|\{.+\}|YOUR_.*|CHANGE_?ME.*)$", re.IGNORECASE),
    re.compile(r"^(?:example|test|dummy|placeholder|todo|fixme)$", re.IGNORECASE),
)

ENTROPY_THRESHOLD = 4.5
MIN_SECRET_LEN = 16
MAX_SECRET_LEN = 200  # real tokens are rarely longer; long strings are usually prose



def shannon_entropy(value: str) -> float:
    """Return Shannon entropy (bits per symbol) of ``value``."""
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


@register
class HardcodedSecretsRule(Rule):
    rule_id = "SAST-SECRET-001"
    title = "Hardcoded credential"
    severity = Severity.MEDIUM
    cwe = "CWE-798"
    remediation = (
        "Store secrets outside source code: use environment variables, "
        "a secret manager (Vault, AWS Secrets Manager) or an encrypted "
        ".env file excluded from version control."
    )
    node_types = (ast.Assign,)

    def inspect(self, node: ast.AST, source_lines: List[str]) -> Iterable[Finding]:
        assert isinstance(node, ast.Assign)
        if not isinstance(node.value, ast.Constant) or not isinstance(node.value.value, str):
            return
        value = node.value.value
        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue
            var = target.id.lower()
            matched_by_name = any(kw in var for kw in SECRET_NAME_KEYWORDS)
            # Ignore multi-line strings and very long strings: real secrets
            # are single-line tokens of bounded length. Long multi-line
            # strings are typically docstrings, prose, or templates.
            matched_by_entropy = (
                MIN_SECRET_LEN <= len(value) <= MAX_SECRET_LEN
                and "\n" not in value
                and " " not in value
                and shannon_entropy(value) >= ENTROPY_THRESHOLD
                and not self._is_placeholder(value)
            )

            if matched_by_name and self._is_placeholder(value):
                continue  # placeholder for documentation, skip

            if matched_by_name:
                yield self._finding(
                    node,
                    f'Hardcoded secret in variable "{target.id}".',
                    source_lines,
                )
            elif matched_by_entropy:
                yield self._finding(
                    node,
                    f'High-entropy string assigned to "{target.id}" '
                    "looks like a credential.",
                    source_lines,
                    confidence="MEDIUM",
                )

    @staticmethod
    def _is_placeholder(value: str) -> bool:
        return any(p.match(value) for p in PLACEHOLDER_PATTERNS)
