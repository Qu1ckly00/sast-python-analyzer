"""Sensitivity analysis of detection-rule thresholds.

For each candidate threshold of the Shannon-entropy parameter used by
SAST-SECRET-001, the script:

1. Patches ``core.rules.hardcoded_secrets.ENTROPY_THRESHOLD`` at runtime.
2. Re-runs the benchmark over the ground-truth dataset.
3. Records the resulting precision, recall and F1 of the SECRET rule.

The output is a markdown table; an accompanying matplotlib chart is
saved as ``images/fig_5_5_sensitivity.png`` for inclusion in the thesis.
"""
from __future__ import annotations
import os
import sys

# Make the project root importable when run as a script.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import importlib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from core.rules import hardcoded_secrets


SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "samples")
THRESHOLDS = [3.5, 4.0, 4.5, 5.0, 5.5]


def _reload_analyzer():
    """Reload analyzer and rule registry to pick up the new threshold."""
    import core.registry as reg
    reg.registry._rules.clear()
    importlib.reload(hardcoded_secrets)
    import core.rules
    importlib.reload(core.rules)
    import core.analyzer
    importlib.reload(core.analyzer)
    return core.analyzer


def measure(threshold: float) -> dict:
    """Return TP/FP/FN/precision/recall/F1 for SECRET at given threshold."""
    hardcoded_secrets.ENTROPY_THRESHOLD = threshold
    analyzer_mod = _reload_analyzer()

    tp = fp = fn = 0
    # Walk vulnerable samples — SECRET-positive should be detected.
    vuln_dir = os.path.join(SAMPLES_DIR, "vulnerable")
    for name in os.listdir(vuln_dir):
        if not name.endswith(".py"):
            continue
        path = os.path.join(vuln_dir, name)
        with open(path, "r", encoding="utf-8") as fh:
            source = fh.read()
        expected_secret_lines = _parse_expected_secret(source)
        findings = analyzer_mod.analyze_file(path)
        actual = {f.line for f in findings if f.rule_id == "SAST-SECRET-001"}
        tp += len(expected_secret_lines & actual)
        fn += len(expected_secret_lines - actual)
        fp += len(actual - expected_secret_lines)

    # Walk safe samples — every SECRET finding is a false positive.
    safe_dir = os.path.join(SAMPLES_DIR, "safe")
    if os.path.isdir(safe_dir):
        for name in os.listdir(safe_dir):
            if not name.endswith(".py"):
                continue
            path = os.path.join(safe_dir, name)
            findings = analyzer_mod.analyze_file(path)
            fp += sum(1 for f in findings if f.rule_id == "SAST-SECRET-001")

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {
        "threshold": threshold,
        "TP": tp, "FP": fp, "FN": fn,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
    }


def _parse_expected_secret(source: str) -> set[int]:
    """Extract line numbers of expected SAST-SECRET-001 findings."""
    import re
    m = re.search(r"#\s*expected_findings:\s*(.+)$", source, re.MULTILINE)
    if not m or m.group(1).strip().upper() == "NONE":
        return set()
    lines = set()
    for token in m.group(1).split(","):
        token = token.strip()
        if "SAST-SECRET-001" in token:
            try:
                lines.add(int(token.split(":")[1]))
            except (IndexError, ValueError):
                pass
    return lines


def plot(results: list[dict], out_path: str) -> None:
    thresholds = [r["threshold"] for r in results]
    precision = [r["precision"] for r in results]
    recall = [r["recall"] for r in results]
    f1 = [r["f1"] for r in results]

    fig, ax = plt.subplots(figsize=(8, 5))
    ax.plot(thresholds, precision, marker="o", label="Precision")
    ax.plot(thresholds, recall, marker="s", label="Recall")
    ax.plot(thresholds, f1, marker="^", label="F1")
    ax.set_xlabel("Поріг ентропії, біт/символ")
    ax.set_ylabel("Значення метрики")
    ax.set_title("Чутливість правила SAST-SECRET-001 до зміни порогу ентропії")
    ax.set_ylim(0.0, 1.05)
    ax.grid(True, linestyle="--", alpha=0.4)
    ax.legend()
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    print(f"chart saved: {out_path}")


def main() -> int:
    results = [measure(t) for t in THRESHOLDS]

    print(f"\n{'thr':>5} {'TP':>3} {'FP':>3} {'FN':>3} {'Prec':>6} {'Rec':>6} {'F1':>6}")
    print("-" * 40)
    for r in results:
        print(f"{r['threshold']:>5} {r['TP']:>3} {r['FP']:>3} {r['FN']:>3} "
              f"{r['precision']:>6} {r['recall']:>6} {r['f1']:>6}")

    out_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "images", "fig_5_5_sensitivity.png",
    )
    plot(results, out_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
