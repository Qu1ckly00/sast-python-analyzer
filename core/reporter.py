"""Output renderers for analyzer findings.

Three formats are provided:

* ``ConsoleReporter`` – human-friendly coloured output for the CLI.
* ``JsonReporter`` – machine-readable report for CI pipelines.
* ``HtmlReporter`` – standalone HTML page suitable for review meetings.

Renderers do not mutate the findings list; they only format it.
"""
from __future__ import annotations
import json
import html
import os
from typing import Iterable, List
from core.finding import Finding
from core.severity import Severity


# Minimal ANSI palette: works in any modern terminal and on Windows 10+
# without enabling colorama.
_ANSI = {
    Severity.CRITICAL: "\033[1;91m",
    Severity.HIGH:     "\033[91m",
    Severity.MEDIUM:   "\033[93m",
    Severity.LOW:      "\033[94m",
    Severity.INFO:     "\033[90m",
}
_RESET = "\033[0m"


class ConsoleReporter:
    """Prints findings to stdout grouped by file."""

    def __init__(self, use_color: bool = True) -> None:
        self.use_color = use_color

    def render(self, findings: Iterable[Finding]) -> str:
        by_file: dict[str, List[Finding]] = {}
        for f in findings:
            by_file.setdefault(f.file_path or "<stdin>", []).append(f)

        out: List[str] = []
        total = 0
        for file_path, items in sorted(by_file.items()):
            items.sort(key=lambda x: (-x.severity.score, x.line))
            out.append(f"\n[file] {file_path}")
            out.append("-" * 72)
            for f in items:
                sev = self._color(f.severity, f.severity.value)
                out.append(
                    f"  line {f.line:>4}  {sev:<22}  {f.rule_id}  {f.cwe or ''}"
                )
                out.append(f"           {f.message}")
                if f.snippet:
                    out.append(f"           > {f.snippet}")
                total += 1
        out.append("")
        out.append(f"Total findings: {total}")
        return "\n".join(out)

    def _color(self, severity: Severity, text: str) -> str:
        if not self.use_color:
            return text
        return f"{_ANSI[severity]}{text}{_RESET}"


class JsonReporter:
    """Serialises findings as a deterministic JSON document."""

    def render(self, findings: Iterable[Finding]) -> str:
        payload = {
            "tool": "AST-SAST",
            "version": "1.0.0",
            "findings": [f.to_dict() for f in findings],
        }
        return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)

    def write(self, findings: Iterable[Finding], path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(self.render(findings))


class SarifReporter:
    """Renders findings as SARIF v2.1.0 (OASIS standard).

    SARIF (Static Analysis Results Interchange Format) is the
    interchange format consumed natively by GitHub Advanced Security,
    Azure DevOps, and Microsoft VS Code. Producing it makes the
    analyzer interoperable with modern DevSecOps pipelines.
    """

    SARIF_VERSION = "2.1.0"
    SARIF_SCHEMA = (
        "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
        "master/Schemata/sarif-schema-2.1.0.json"
    )

    _SEVERITY_TO_SARIF = {
        Severity.CRITICAL: "error",
        Severity.HIGH:     "error",
        Severity.MEDIUM:   "warning",
        Severity.LOW:      "note",
        Severity.INFO:     "note",
    }

    def render(self, findings: Iterable[Finding]) -> str:
        items = list(findings)
        rules_seen: dict[str, Finding] = {}
        for f in items:
            rules_seen.setdefault(f.rule_id, f)

        rules_block = [
            {
                "id": rid,
                "name": (proto.title or rid).replace(" ", ""),
                "shortDescription": {"text": proto.title or rid},
                "fullDescription":  {"text": proto.remediation or proto.title},
                "helpUri":          f"https://cwe.mitre.org/data/definitions/"
                                    f"{(proto.cwe or '').replace('CWE-', '')}.html"
                                    if proto.cwe else "",
                "properties": {"cwe": proto.cwe or "", "severity": proto.severity.value},
            }
            for rid, proto in rules_seen.items()
        ]

        results_block = [
            {
                "ruleId": f.rule_id,
                "level":  self._SEVERITY_TO_SARIF[f.severity],
                "message": {"text": f.message},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": (f.file_path or "").replace("\\", "/")},
                        "region": {"startLine": max(1, f.line), "startColumn": max(1, f.column + 1)},
                    }
                }],
                "properties": {
                    "cwe": f.cwe or "",
                    "confidence": f.confidence,
                    "snippet": f.snippet or "",
                },
            }
            for f in items
        ]

        sarif = {
            "$schema": self.SARIF_SCHEMA,
            "version": self.SARIF_VERSION,
            "runs": [{
                "tool": {
                    "driver": {
                        "name":            "AST-SAST",
                        "version":         "1.0.0",
                        "informationUri":  "https://example.org/ast-sast",
                        "rules":           rules_block,
                    }
                },
                "results": results_block,
            }],
        }
        return json.dumps(sarif, ensure_ascii=False, indent=2)

    def write(self, findings: Iterable[Finding], path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(self.render(findings))


class HtmlReporter:
    """Renders a standalone HTML report (no external assets)."""

    _TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>AST-SAST report</title>
<style>
 body{{font-family:system-ui,sans-serif;margin:24px;color:#222}}
 h1{{margin:0 0 4px}}
 .meta{{color:#666;margin-bottom:24px}}
 table{{border-collapse:collapse;width:100%}}
 th,td{{padding:8px 10px;border-bottom:1px solid #eee;text-align:left;vertical-align:top}}
 th{{background:#fafafa;font-weight:600}}
 .sev{{display:inline-block;padding:2px 8px;border-radius:10px;color:#fff;font-size:12px}}
 code{{background:#f4f4f4;padding:1px 4px;border-radius:3px}}
</style></head><body>
<h1>AST-SAST report</h1>
<div class="meta">Findings: {total}</div>
<table><thead><tr>
 <th>#</th><th>Severity</th><th>Rule</th><th>File</th><th>Line</th>
 <th>Message</th><th>CWE</th>
</tr></thead><tbody>
{rows}
</tbody></table>
</body></html>"""

    def render(self, findings: Iterable[Finding]) -> str:
        items = list(findings)
        items.sort(key=lambda x: (-x.severity.score, x.file_path, x.line))
        rows = []
        for i, f in enumerate(items, 1):
            rows.append(
                "<tr>"
                f"<td>{i}</td>"
                f'<td><span class="sev" style="background:{f.severity.color}">{html.escape(f.severity.value)}</span></td>'
                f"<td>{html.escape(f.rule_id)}<br><small>{html.escape(f.title)}</small></td>"
                f"<td><code>{html.escape(f.file_path or '')}</code></td>"
                f"<td>{f.line}</td>"
                f"<td>{html.escape(f.message)}"
                + (f"<br><code>{html.escape(f.snippet)}</code>" if f.snippet else "")
                + (f'<br><small>Fix: {html.escape(f.remediation)}</small>' if f.remediation else "")
                + "</td>"
                f"<td>{html.escape(f.cwe or '')}</td>"
                "</tr>"
            )
        return self._TEMPLATE.format(total=len(items), rows="\n".join(rows))

    def write(self, findings: Iterable[Finding], path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(self.render(findings))
