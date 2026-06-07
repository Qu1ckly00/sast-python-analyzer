"""Unit tests for individual rules.

Run::

    python -m unittest tests.test_rules
"""
from __future__ import annotations
import os
import re
import unittest
from typing import Dict, List
from core.analyzer import analyze_source, analyze_file

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "samples")
EXPECTED_RE = re.compile(r"#\s*expected_findings:\s*(.+)$", re.MULTILINE)


def parse_expected(source: str) -> Dict[str, List[int]]:
    """Read the magic 'expected_findings' comment from a ground-truth file."""
    expected: Dict[str, List[int]] = {}
    match = EXPECTED_RE.search(source)
    if not match or match.group(1).strip().upper() == "NONE":
        return expected
    for token in match.group(1).split(","):
        token = token.strip()
        if not token:
            continue
        rule_id, _, line_str = token.partition(":")
        expected.setdefault(rule_id, []).append(int(line_str))
    return expected


class GroundTruthTests(unittest.TestCase):
    """Compare findings against the inline ground-truth annotations."""

    def _collect_samples(self, subdir: str):
        directory = os.path.join(SAMPLES_DIR, subdir)
        for name in sorted(os.listdir(directory)):
            if name.endswith(".py"):
                yield os.path.join(directory, name)

    def test_vulnerable_samples(self):
        for path in self._collect_samples("vulnerable"):
            with self.subTest(path=os.path.basename(path)):
                with open(path, "r", encoding="utf-8") as fh:
                    src = fh.read()
                expected = parse_expected(src)
                findings = analyze_file(path)
                actual: Dict[str, List[int]] = {}
                for f in findings:
                    actual.setdefault(f.rule_id, []).append(f.line)
                for rid, lines in expected.items():
                    self.assertIn(rid, actual, f"Rule {rid} not triggered in {path}")
                    for ln in lines:
                        self.assertIn(ln, actual[rid], f"Expected {rid} at line {ln} in {path}")

    def test_safe_sample(self):
        for path in self._collect_samples("safe"):
            with self.subTest(path=os.path.basename(path)):
                findings = analyze_file(path)
                non_info = [f for f in findings if f.severity.value != "INFO"]
                self.assertEqual(non_info, [], f"False positives in {path}: {non_info}")


class SmokeTests(unittest.TestCase):
    def test_empty_source(self):
        self.assertEqual(analyze_source(""), [])

    def test_parse_error(self):
        findings = analyze_source("def x(:\n")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "SAST-PARSE-ERR")


if __name__ == "__main__":
    unittest.main()
