"""Flask web interface for the AST-SAST scanner.

The route renders an HTML form that accepts a Python snippet and returns
findings produced by :func:`core.analyzer.analyze_source`. The analyzer
is invoked on the server but the submitted code is never executed; only
its AST is parsed, so the endpoint is safe to expose locally.
"""
from __future__ import annotations
from flask import Flask, render_template, request
from core.analyzer import analyze_source
from core.registry import registry

app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def index():
    code = ""
    findings = None
    if request.method == "POST":
        code = request.form.get("code_input", "")
        if code.strip():
            findings = [f.to_dict() for f in analyze_source(code, file_path="<web>")]
    return render_template(
        "index.html",
        results=findings,
        code_to_check=code,
        rule_ids=sorted(registry.all_ids()),
    )


@app.route("/rules")
def rules():
    return {"rules": sorted(registry.all_ids())}


if __name__ == "__main__":
    app.run(debug=False, host="127.0.0.1", port=5000)
