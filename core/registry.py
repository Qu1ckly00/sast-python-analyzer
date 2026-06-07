"""Global rule registry.

Implements the registry pattern: rule classes self-register via the
``@register`` decorator. The AST dispatcher in :mod:`core.analyzer` then
materialises all active rules without hard-coded imports of each one.
"""
from __future__ import annotations
from typing import Dict, Type, List, Optional
from core.rules.base import Rule


class RuleRegistry:
    """Container for registered rule classes."""

    def __init__(self) -> None:
        self._rules: Dict[str, Type[Rule]] = {}

    def register(self, rule_cls: Type[Rule]) -> Type[Rule]:
        if not issubclass(rule_cls, Rule):
            raise TypeError(f"{rule_cls.__name__} is not a subclass of Rule")
        instance = rule_cls()  # validate the rule
        if instance.rule_id in self._rules:
            raise ValueError(f"Duplicate rule id: {instance.rule_id}")
        self._rules[instance.rule_id] = rule_cls
        return rule_cls

    def instances(self, disabled: Optional[List[str]] = None) -> List[Rule]:
        disabled = disabled or []
        return [cls() for rid, cls in self._rules.items() if rid not in disabled]

    def all_ids(self) -> List[str]:
        return list(self._rules.keys())


registry = RuleRegistry()


def register(cls: Type[Rule]) -> Type[Rule]:
    """Convenience decorator wrapping :meth:`RuleRegistry.register`."""
    return registry.register(cls)
