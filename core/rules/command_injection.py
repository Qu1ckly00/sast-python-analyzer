"""Detection of OS command injection (CWE-78).

The rule reports two patterns:

* Any call to ``os.system`` / ``os.popen`` / ``commands.getoutput`` whose
  argument is a dynamically built string.
* Any ``subprocess.{run,Popen,call,check_output,check_call}`` invocation
  with ``shell=True``. The combination of an arbitrary shell and a
  dynamic string is the canonical command injection sink in Python.
"""
from __future__ import annotations
import ast
from typing import Iterable, List, Optional, Tuple
from core.rules.base import Rule
from core.severity import Severity
from core.finding import Finding
from core.registry import register


OS_SHELL_SINKS = {
    ("os", "system"),
    ("os", "popen"),
    ("commands", "getoutput"),
    ("commands", "getstatusoutput"),
}

SUBPROCESS_FUNCS = {"run", "Popen", "call", "check_output", "check_call", "getoutput"}


@register
class CommandInjectionRule(Rule):
    rule_id = "SAST-CMDI-001"
    title = "OS command injection"
    severity = Severity.CRITICAL
    cwe = "CWE-78"
    remediation = (
        "Pass arguments as a list and keep shell=False (the default). "
        "When a shell is unavoidable, sanitize input with shlex.quote() "
        "and validate against an allow-list of expected values."
    )
    node_types = (ast.Call,)

    def inspect(self, node: ast.AST, source_lines: List[str]) -> Iterable[Finding]:
        assert isinstance(node, ast.Call)
        pair = self._module_attr(node.func)

        if pair in OS_SHELL_SINKS and node.args and self._is_dynamic(node.args[0]):
            module, attr = pair
            yield self._finding(
                node,
                f"{module}.{attr}() invoked with a dynamically built "
                "command string – classic command injection sink.",
                source_lines,
            )
            return

        if self._is_subprocess_call(node.func) and self._has_shell_true(node):
            cmd_arg = node.args[0] if node.args else None
            confidence = "HIGH" if cmd_arg is not None and self._is_dynamic(cmd_arg) else "MEDIUM"
            yield self._finding(
                node,
                "subprocess call with shell=True executes the command via "
                "the shell; combined with user input this enables command injection.",
                source_lines,
                confidence=confidence,
            )

    @staticmethod
    def _module_attr(func: ast.AST) -> Optional[Tuple[str, str]]:
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            return (func.value.id, func.attr)
        return None

    @staticmethod
    def _is_subprocess_call(func: ast.AST) -> bool:
        if isinstance(func, ast.Attribute) and func.attr in SUBPROCESS_FUNCS:
            owner = func.value
            return isinstance(owner, ast.Name) and owner.id == "subprocess"
        return False

    @staticmethod
    def _has_shell_true(node: ast.Call) -> bool:
        for kw in node.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                return True
        return False

    @staticmethod
    def _is_dynamic(arg: ast.AST) -> bool:
        if isinstance(arg, (ast.JoinedStr, ast.BinOp, ast.Name)):
            return True
        if (
            isinstance(arg, ast.Call)
            and isinstance(arg.func, ast.Attribute)
            and arg.func.attr in {"format", "join"}
        ):
            return True
        return False
