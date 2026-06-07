"""Ground truth: contains 2 SSTI findings."""
# expected_findings: SAST-SSTI-001:8, SAST-SSTI-001:11
from jinja2 import Template, Environment
from flask import request

def render_a():
    user = request.args["name"]
    return Template("Hello " + user).render()

def render_b(env: Environment, blob: str):
    return env.from_string(f"<h1>{blob}</h1>").render()
