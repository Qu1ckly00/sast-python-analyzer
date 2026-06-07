"""Bundle of vulnerability detection rules.

Importing the submodules below auto-registers every rule in the global
registry via the ``@register`` decorator declared in :mod:`core.registry`.
"""
from core.rules import (
    rce,
    sql_injection,
    xss,
    hardcoded_secrets,
    path_traversal,
    ssrf,
    insecure_deserialization,
    command_injection,
    ssti,
    xxe,
    weak_auth,
)

__all__ = [
    "rce",
    "sql_injection",
    "xss",
    "hardcoded_secrets",
    "path_traversal",
    "ssrf",
    "insecure_deserialization",
    "command_injection",
    "ssti",
    "xxe",
    "weak_auth",
]
