"""Ground truth: contains 3 XSS findings."""
# expected_findings: SAST-XSS-001:7, SAST-XSS-001:10, SAST-XSS-001:13
from flask import render_template_string, Markup
from django.utils.safestring import mark_safe

def render_a(name):
    return render_template_string("<h1>Hello %s</h1>" % name)

def render_b(payload):
    return Markup(payload)

def render_c(payload):
    return mark_safe(payload)
