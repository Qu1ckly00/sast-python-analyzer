"""Quality benchmark for the AST-SAST scanner.

The script walks ``tests/samples`` and uses the inline ``expected_findings``
annotations as ground truth to compute Precision, Recall and F1-score.

If ``bandit`` and/or ``semgrep`` are installed (PATH lookup), it also runs
them on the same dataset and prints a side-by-side comparison. This is
the dataset used in Section 3 of the thesis to substantiate quantitative
claims about the proposed AST approach.

Usage::

    python -m tests.benchmark
    python -m tests.benchmark --json metrics.json
"""
from __future__ import annotations
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from collections import defaultdict
from typing import Dict, List, Set, Tuple

from core.analyzer import analyze_file

SAMPLES = os.path.join(os.path.dirname(__file__), "samples")
EXPECTED_RE = re.compile(r"#\s*expected_findings:\s*(.+)$", re.MULTILINE)

# Mapping from each tool's native category to a canonical bucket used by
# the benchmark. Without normalisation tools cannot be compared because
# they use different rule taxonomies.
CANON_BUCKETS = {"RCE", "SQLI", "XSS", "SECRET", "PATH", "SSRF",
                 "DESERIAL", "CMDI", "SSTI", "XXE", "AUTH"}

OURS_TO_BUCKET = {
    "SAST-RCE-001":     "RCE",
    "SAST-SQLI-001":    "SQLI",
    "SAST-XSS-001":     "XSS",
    "SAST-SECRET-001":  "SECRET",
    "SAST-PATH-001":    "PATH",
    "SAST-SSRF-001":    "SSRF",
    "SAST-DESERIAL-001": "DESERIAL",
    "SAST-CMDI-001":    "CMDI",
    "SAST-SSTI-001":    "SSTI",
    "SAST-XXE-001":     "XXE",
    "SAST-AUTH-001":    "AUTH",
}

BANDIT_TO_BUCKET = {
    "B102": "RCE", "B307": "RCE",
    "B608": "SQLI",
    "B703": "XSS", "B704": "XSS",
    "B105": "SECRET", "B106": "SECRET", "B107": "SECRET",
    "B310": "SSRF",
    "B301": "DESERIAL", "B403": "DESERIAL", "B506": "DESERIAL",
    "B602": "CMDI", "B603": "CMDI", "B604": "CMDI", "B605": "CMDI", "B606": "CMDI", "B607": "CMDI",
    "B313": "XXE", "B314": "XXE", "B315": "XXE", "B316": "XXE", "B317": "XXE",
    "B318": "XXE", "B319": "XXE", "B320": "XXE",
}


def load_ground_truth() -> Dict[str, Set[Tuple[str, int]]]:
    """Return {file_path: {(bucket, line), ...}}."""
    truth: Dict[str, Set[Tuple[str, int]]] = {}
    for root, _dirs, files in os.walk(SAMPLES):
        for name in files:
            if not name.endswith(".py"):
                continue
            path = os.path.join(root, name)
            with open(path, "r", encoding="utf-8") as fh:
                src = fh.read()
            match = EXPECTED_RE.search(src)
            findings: Set[Tuple[str, int]] = set()
            if match and match.group(1).strip().upper() != "NONE":
                for token in match.group(1).split(","):
                    token = token.strip()
                    if not token:
                        continue
                    rid, _, line_str = token.partition(":")
                    bucket = OURS_TO_BUCKET.get(rid.strip())
                    if bucket:
                        findings.add((bucket, int(line_str)))
            truth[path] = findings
    return truth


def collect_ours() -> Dict[str, Set[Tuple[str, int]]]:
    out: Dict[str, Set[Tuple[str, int]]] = defaultdict(set)
    for root, _d, files in os.walk(SAMPLES):
        for n in files:
            if not n.endswith(".py"):
                continue
            path = os.path.join(root, n)
            for f in analyze_file(path):
                bucket = OURS_TO_BUCKET.get(f.rule_id)
                if bucket:
                    out[path].add((bucket, f.line))
    return out


def collect_bandit() -> Dict[str, Set[Tuple[str, int]]]:
    if not shutil.which("bandit"):
        return {}
    out: Dict[str, Set[Tuple[str, int]]] = defaultdict(set)
    try:
        proc = subprocess.run(
            ["bandit", "-r", SAMPLES, "-f", "json", "-q"],
            capture_output=True, text=True, timeout=120,
        )
        data = json.loads(proc.stdout or "{}")
    except Exception:
        return {}
    for issue in data.get("results", []):
        bucket = BANDIT_TO_BUCKET.get(issue.get("test_id"))
        if not bucket:
            continue
        path = os.path.abspath(issue.get("filename", ""))
        line = int(issue.get("line_number", 0))
        out[path].add((bucket, line))
    return out


def collect_semgrep() -> Dict[str, Set[Tuple[str, int]]]:
    if not shutil.which("semgrep"):
        return {}
    out: Dict[str, Set[Tuple[str, int]]] = defaultdict(set)
    try:
        proc = subprocess.run(
            ["semgrep", "--config", "p/python", "--json", "--quiet", SAMPLES],
            capture_output=True, text=True, timeout=300,
        )
        data = json.loads(proc.stdout or "{}")
    except Exception:
        return {}
    for r in data.get("results", []):
        check_id = (r.get("check_id") or "").lower()
        bucket = None
        if "sql" in check_id: bucket = "SQLI"
        elif "xss" in check_id: bucket = "XSS"
        elif "secret" in check_id or "hardcoded" in check_id: bucket = "SECRET"
        elif "path-traversal" in check_id or "open-from-user" in check_id: bucket = "PATH"
        elif "ssrf" in check_id or "url-from-user" in check_id: bucket = "SSRF"
        elif "pickle" in check_id or "yaml-load" in check_id or "deserialization" in check_id: bucket = "DESERIAL"
        elif "shell-true" in check_id or "command-injection" in check_id or "subprocess" in check_id: bucket = "CMDI"
        elif "eval" in check_id or "exec" in check_id: bucket = "RCE"
        if bucket:
            path = os.path.abspath(r.get("path", ""))
            line = int(r.get("start", {}).get("line", 0))
            out[path].add((bucket, line))
    return out


def score(truth: Dict[str, Set], predicted: Dict[str, Set]) -> Dict[str, float]:
    """Compute precision/recall/F1 with line-tolerant matching (+/-1 line)."""
    tp = fp = fn = 0
    for path, true_set in truth.items():
        pred_set = predicted.get(path, set()) | predicted.get(os.path.abspath(path), set())
        matched_truth: Set = set()
        matched_pred: Set = set()
        for tb, tl in true_set:
            for pb, pl in pred_set:
                if (pb, pl) in matched_pred:
                    continue
                if tb == pb and abs(tl - pl) <= 1:
                    matched_truth.add((tb, tl))
                    matched_pred.add((pb, pl))
                    break
        tp += len(matched_truth)
        fn += len(true_set - matched_truth)
        fp += len(pred_set - matched_pred)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall    = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {"TP": tp, "FP": fp, "FN": fn,
            "precision": round(precision, 3),
            "recall":    round(recall, 3),
            "f1":        round(f1, 3)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", help="Write metrics to JSON file")
    args = parser.parse_args()

    truth = load_ground_truth()

    tools = {}
    t0 = time.perf_counter()
    tools["AST-SAST (ours)"] = collect_ours()
    ours_time = time.perf_counter() - t0

    t1 = time.perf_counter()
    bandit = collect_bandit()
    bandit_time = time.perf_counter() - t1
    if bandit:
        tools["Bandit"] = bandit

    t2 = time.perf_counter()
    semgrep = collect_semgrep()
    semgrep_time = time.perf_counter() - t2
    if semgrep:
        tools["Semgrep"] = semgrep

    metrics = {name: score(truth, preds) for name, preds in tools.items()}
    metrics["AST-SAST (ours)"]["time_sec"] = round(ours_time, 3)
    if "Bandit" in metrics:    metrics["Bandit"]["time_sec"] = round(bandit_time, 3)
    if "Semgrep" in metrics:   metrics["Semgrep"]["time_sec"] = round(semgrep_time, 3)

    print(f"{'Tool':<20} {'TP':>4} {'FP':>4} {'FN':>4} {'Prec':>6} {'Rec':>6} {'F1':>6} {'Time':>7}")
    print("-" * 64)
    for name, m in metrics.items():
        print(f"{name:<20} {m['TP']:>4} {m['FP']:>4} {m['FN']:>4} "
              f"{m['precision']:>6} {m['recall']:>6} {m['f1']:>6} "
              f"{m.get('time_sec', 0):>7}")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(metrics, fh, indent=2)
        print(f"\nMetrics saved to {args.json}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
