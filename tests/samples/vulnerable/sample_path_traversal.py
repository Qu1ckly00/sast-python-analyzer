"""Ground truth: contains 2 path traversal findings."""
# expected_findings: SAST-PATH-001:7, SAST-PATH-001:10
from flask import request, send_file
import os

def download():
    return send_file(request.args["filename"])

def read_log():
    path = os.path.join("/var/log", request.args.get("name", ""))
    return open(path).read()
