"""Dataclass describing a single vulnerability finding."""
from dataclasses import dataclass, asdict, field
from typing import Optional, Dict, Any
from core.severity import Severity


@dataclass
class Finding:
    """Unified representation of a vulnerability found by a rule.

    Field names are deliberately close to the SARIF schema so that the
    reporter can later emit SARIF-compatible JSON consumable by IDE
    plugins, GitHub Advanced Security and other DevSecOps platforms.
    """
    rule_id: str
    title: str
    message: str
    severity: Severity
    line: int
    column: int = 0
    file_path: str = ""
    cwe: Optional[str] = None
    snippet: Optional[str] = None
    confidence: str = "HIGH"
    remediation: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data
