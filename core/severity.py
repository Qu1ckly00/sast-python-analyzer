"""Severity classification aligned with CVSS v3.1 qualitative ratings."""
from enum import Enum


class Severity(str, Enum):
    """Severity levels used across the analyzer.

    Values are English to remain consistent with the SARIF specification
    and to keep findings interoperable with third-party tooling.
    """
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def score(self) -> int:
        """Numeric weight used for sorting findings."""
        return {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }[self]

    @property
    def color(self) -> str:
        """HEX color used by the HTML reporter."""
        return {
            Severity.CRITICAL: "#8B0000",
            Severity.HIGH: "#DC3545",
            Severity.MEDIUM: "#FD7E14",
            Severity.LOW: "#FFC107",
            Severity.INFO: "#0DCAF0",
        }[self]
