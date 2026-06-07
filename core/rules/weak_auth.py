"""Detection of weak authentication patterns (OWASP A07, CWE-287).

Covers two intra-procedural patterns frequently classified as A07
Identification and Authentication Failures:

1. Hardcoded credential comparison — checks like::

       if password == "admin123":
       if user == "admin" and pwd == "secret":

   These embed credentials in code, bypass any password hashing and
   make rotation impossible.

2. Insecure password hashing — calls to MD5/SHA1 with a variable that
   smells like a password::

       hashlib.md5(password.encode()).hexdigest()

   MD5 and SHA1 are not collision-resistant and not designed for
   password storage; bcrypt/argon2/scrypt should be used instead.
"""
from __future__ import annotations
import ast
from typing import Iterable, List, Optional
from core.rules.base import Rule
from core.severity import Severity
from core.finding import Finding
from core.registry import register


CREDENTIAL_NAMES = (
    "password", "passwd", "pwd",
    "secret", "token", "api_key", "apikey",
    "auth", "credential",
)

WEAK_HASHES = {"md5", "sha1", "new"}  # hashlib.new("md5", ...) is also weak


def _name_looks_like_credential(name: str) -> bool:
    n = name.lower()
    return any(kw in n for kw in CREDENTIAL_NAMES)


@register
class WeakAuthenticationRule(Rule):
    rule_id = "SAST-AUTH-001"
    title = "Weak authentication pattern"
    severity = Severity.HIGH
    cwe = "CWE-287"
    remediation = (
        "Store passwords hashed with bcrypt/argon2/scrypt and compare via "
        "constant-time hash verification. Never hardcode credentials; load "
        "them from a secret manager or environment variable."
    )
    node_types = (ast.Compare, ast.Call, ast.BoolOp)

    def inspect(self, node: ast.AST, source_lines: List[str]) -> Iterable[Finding]:
        if isinstance(node, ast.Compare):
            yield from self._check_compare(node, source_lines)
        elif isinstance(node, ast.Call):
            yield from self._check_hash_call(node, source_lines)
        elif isinstance(node, ast.BoolOp):
            yield from self._check_boolop_credentials(node, source_lines)

    def _check_compare(self, node: ast.Compare, source_lines: List[str]) -> Iterable[Finding]:
        # if password == "literal"  or  if "literal" == password
        left = node.left
        if not node.comparators or not isinstance(node.ops[0], ast.Eq):
            return
        right = node.comparators[0]
        for var_node, lit_node in ((left, right), (right, left)):
            if (
                isinstance(var_node, ast.Name)
                and _name_looks_like_credential(var_node.id)
                and isinstance(lit_node, ast.Constant)
                and isinstance(lit_node.value, str)
                and len(lit_node.value) > 0
            ):
                yield self._finding(
                    node,
                    f"Hardcoded credential comparison: variable \"{var_node.id}\" "
                    "is checked against a string literal — bypasses password hashing.",
                    source_lines,
                )
                return

    def _check_hash_call(self, node: ast.Call, source_lines: List[str]) -> Iterable[Finding]:
        # hashlib.md5(password.encode()) or md5(password)
        callee = self._callee_name(node.func)
        if callee not in WEAK_HASHES:
            return
        if not node.args:
            return
        arg = node.args[0]
        # arg could be Name, Call (e.g. password.encode()) or Attribute
        target_name = self._first_name(arg)
        if target_name and _name_looks_like_credential(target_name):
            yield self._finding(
                node,
                f"Weak hash ({callee}) applied to a credential-like value "
                f"\"{target_name}\" — use bcrypt/argon2/scrypt for passwords.",
                source_lines,
            )

    def _check_boolop_credentials(self, node: ast.BoolOp, source_lines: List[str]) -> Iterable[Finding]:
        # if user == "admin" and password == "secret"
        # Avoid double-reporting when individual Compares already triggered.
        # This visitor only adds an EXTRA finding if BOTH parts are
        # credential-comparisons — pure documentation, not a strict check.
        return ()

    @staticmethod
    def _callee_name(func: ast.AST) -> Optional[str]:
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            return func.attr
        return None

    @staticmethod
    def _first_name(node: ast.AST) -> Optional[str]:
        """Return the leftmost identifier name in `node`, if any.

        Used to dig past .encode() / .decode() wrappers around the
        variable under inspection: ``password.encode()`` → ``password``.
        """
        cur = node
        while True:
            if isinstance(cur, ast.Name):
                return cur.id
            if isinstance(cur, ast.Call):
                cur = cur.func
                continue
            if isinstance(cur, ast.Attribute):
                cur = cur.value
                continue
            return None
