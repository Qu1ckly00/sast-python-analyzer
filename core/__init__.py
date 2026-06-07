"""Ядро SAST-аналізатора: AST-обхід, правила, звітність."""
from core.analyzer import SecurityAnalyzer, analyze_source, analyze_file
from core.finding import Finding
from core.severity import Severity

__all__ = ["SecurityAnalyzer", "analyze_source", "analyze_file", "Finding", "Severity"]
__version__ = "1.0.0"
