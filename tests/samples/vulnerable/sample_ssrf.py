"""Ground truth: contains 2 SSRF findings."""
# expected_findings: SAST-SSRF-001:7
import requests
from flask import request

def fetch_a():
    return requests.get(request.args["url"])

def fetch_b():
    target = f"https://{request.args['host']}/api"
    return requests.post(target)
