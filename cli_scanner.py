"""Command-line entry point for the AST-SAST scanner.

Examples
--------
Scan a single file with the default ruleset::

    python cli_scanner.py path/to/module.py

Scan a directory recursively and emit a JSON report::

    python cli_scanner.py ./src --json report.json

Disable a noisy rule and produce an HTML dashboard::

    python cli_scanner.py ./src --disable SAST-SECRET-001 --html report.html
"""
from __future__ import annotations
import argparse
import os
import sys
from typing import List
from core.analyzer import analyze_file
from core.finding import Finding
from core.reporter import ConsoleReporter, JsonReporter, HtmlReporter, SarifReporter
from core.registry import registry


def discover_python_files(target: str) -> List[str]:
    """Return ``[target]`` for a single file or every *.py under a directory."""
    if os.path.isfile(target):
        return [target] if target.endswith(".py") else []
    files: List[str] = []
    for root, _dirs, names in os.walk(target):
        if any(part.startswith(".") for part in root.split(os.sep)):
            continue
        for name in names:
            if name.endswith(".py"):
                files.append(os.path.join(root, name))
    return files


def parse_args(argv: List[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="ast-sast",
        description="AST-based static analyzer for Python vulnerabilities.",
    )
    parser.add_argument("target", nargs="?", default=".", help="File or directory to scan")
    parser.add_argument("--json", metavar="PATH", help="Write JSON report to PATH")
    parser.add_argument("--html", metavar="PATH", help="Write HTML report to PATH")
    parser.add_argument("--sarif", metavar="PATH", help="Write SARIF v2.1.0 report to PATH")
    parser.add_argument(
        "--disable",
        action="append",
        default=[],
        metavar="RULE_ID",
        help="Disable a rule by id (can be repeated)",
    )
    parser.add_argument("--list-rules", action="store_true", help="Show available rules and exit")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colours")
    parser.add_argument(
        "--fail-on",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default="HIGH",
        help="Exit with non-zero status when any finding meets/exceeds this severity",
    )
    return parser.parse_args(argv)


def _exit_code(findings: List[Finding], threshold: str) -> int:
    order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    th = order.index(threshold)
    for f in findings:
        if order.index(f.severity.value) >= th:
            return 1
    return 0


def main(argv: List[str] | None = None) -> int:
    args = parse_args(argv)

    if args.list_rules:
        for rid in sorted(registry.all_ids()):
            print(rid)
        return 0

    if not os.path.exists(args.target):
        print(f"Path not found: {args.target}", file=sys.stderr)
        return 2

    files = discover_python_files(args.target)
    if not files:
        print("No Python files to scan.")
        return 0

    findings: List[Finding] = []
    for path in files:
        findings.extend(analyze_file(path))

    console = ConsoleReporter(use_color=not args.no_color)
    print(console.render(findings))

    if args.json:
        JsonReporter().write(findings, args.json)
        print(f"JSON report written to {args.json}")
    if args.html:
        HtmlReporter().write(findings, args.html)
        print(f"HTML report written to {args.html}")
    if args.sarif:
        SarifReporter().write(findings, args.sarif)
        print(f"SARIF report written to {args.sarif}")

    return _exit_code(findings, args.fail_on)


if __name__ == "__main__":
    sys.exit(main())
