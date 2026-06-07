# AST-SAST — AST-based Static Application Security Testing for Python

AST-SAST is a static source-code analyzer that detects security
vulnerabilities in Python code by traversing its Abstract Syntax Tree
(AST). The project is the engineering part of a bachelor thesis for
specialty *122 Computer Sciences* and is intentionally designed as an
academic reference implementation: every component is small, isolated
and easy to reason about.

## Features

The analyzer currently ships with eight detection rules covering the
most prevalent categories of the OWASP Top 10 for Python applications:

| Rule ID            | Vulnerability                  | CWE      | Severity |
|--------------------|--------------------------------|----------|----------|
| SAST-RCE-001       | Arbitrary code execution       | CWE-95   | CRITICAL |
| SAST-SQLI-001      | SQL injection                  | CWE-89   | HIGH     |
| SAST-XSS-001       | Cross-Site Scripting           | CWE-79   | HIGH     |
| SAST-SECRET-001    | Hardcoded credentials          | CWE-798  | MEDIUM   |
| SAST-PATH-001      | Path traversal                 | CWE-22   | HIGH     |
| SAST-SSRF-001      | Server-Side Request Forgery    | CWE-918  | HIGH     |
| SAST-DESERIAL-001  | Insecure deserialization       | CWE-502  | CRITICAL |
| SAST-CMDI-001      | OS command injection           | CWE-78   | CRITICAL |
| SAST-SSTI-001      | Server-Side Template Injection | CWE-1336 | CRITICAL |
| SAST-XXE-001       | XML External Entity expansion  | CWE-611  | HIGH     |

Additional capabilities:

* **CLI tool** (`cli_scanner.py`) with four output formats — console,
  JSON, HTML and **SARIF v2.1.0** (OASIS standard, consumed by GitHub
  Advanced Security and Azure DevOps) — and a configurable
  `--fail-on` severity gate for CI.
* **GitHub Actions workflow** (`.github/workflows/sast.yml`) that runs
  the scanner on every push and uploads SARIF results to the GitHub
  Security tab.
* **Web UI** (`web_app.py`) — Flask service for ad-hoc snippet review.
* **Benchmark harness** (`tests/benchmark.py`) — measures Precision,
  Recall and F1-score on the bundled ground-truth dataset and produces
  side-by-side comparisons with Bandit and Semgrep when those tools
  are installed.

## Architecture

```
                  +----------------------+
  source code --> | ast.parse()          |
                  +----------+-----------+
                             |
                             v
                  +----------------------+
                  | SecurityAnalyzer     |   <-- AST dispatcher
                  | (core/analyzer.py)   |
                  +----------+-----------+
                             |
                routing by node type (O(1) per node)
                             |
        +------+------+------+------+------+------+--------+--------+
        v      v      v      v      v      v      v        v
       RCE  SQLi   XSS  Secrets PathT  SSRF Deserial   CmdI
        \\_____\\____\\______\\______/______/______/________/
                                 |
                                 v
                              Finding[]
                                 |
                  +--------------+--------------+
                  v              v              v
            ConsoleReporter  JsonReporter   HtmlReporter
```

The design follows two well-known patterns:

* **Visitor** for AST traversal — every Python node is dispatched
  exactly once.
* **Strategy / Registry** for rules — each rule is a self-contained
  class that registers itself in the global rule registry via the
  `@register` decorator. Adding a new vulnerability category does not
  require modifying any existing code; one creates a new file under
  `core/rules/` and the rule is auto-discovered.

## Installation

```bash
git clone <repo>
cd dyplom44
python -m venv .venv
.venv\Scripts\activate          # Windows
pip install -r requirements.txt
```

Python 3.10 or newer is required.

## Usage

### Command line

```bash
# scan a single file
python cli_scanner.py path/to/module.py

# scan a directory and emit JSON + HTML reports
python cli_scanner.py ./src --json report.json --html report.html

# emit a SARIF report consumable by GitHub Security / VS Code
python cli_scanner.py ./src --sarif report.sarif

# list active rules
python cli_scanner.py --list-rules

# disable a noisy rule
python cli_scanner.py ./src --disable SAST-SECRET-001

# CI gate: exit with non-zero status on HIGH or CRITICAL findings
python cli_scanner.py ./src --fail-on HIGH
```

### Web interface

```bash
python web_app.py
# open http://127.0.0.1:5000
```

## Testing

```bash
# unit + ground-truth tests
python -m unittest discover -s tests

# quantitative benchmark (Precision / Recall / F1)
python -m tests.benchmark --json metrics.json
```

The bundled dataset in `tests/samples/` contains *vulnerable* fixtures
with inline `expected_findings` annotations and *safe* fixtures used to
measure the false-positive rate.

## Limitations

* The analyzer is purely **syntactic / intra-procedural**: it has no
  inter-procedural data-flow engine, so vulnerabilities that depend on
  cross-function taint propagation will be missed.
* The target language is **Python only**. The codebase is structured so
  that an additional front-end (for example based on `tree-sitter`)
  could be plugged in without rewriting the rule layer.
* Confidence levels are advisory; in academic benchmarks every finding
  is treated as a positive regardless of confidence.

## License

Educational use only — see thesis defense materials for details.
