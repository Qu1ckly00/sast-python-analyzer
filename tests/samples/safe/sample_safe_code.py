"""Ground truth: zero findings expected. The code uses the recommended fixes."""
# expected_findings: NONE
import os
import sqlite3
import subprocess
import yaml
import json
from flask import request

DEFAULT_LOGS = "/var/log/app"

def lookup(cursor, name):
    cursor.execute("SELECT * FROM users WHERE name = ?", (name,))

def safe_path(name):
    base = os.path.realpath(DEFAULT_LOGS)
    candidate = os.path.realpath(os.path.join(base, name))
    if not candidate.startswith(base + os.sep):
        raise ValueError("escape")
    return candidate

def safe_yaml(blob):
    return yaml.safe_load(blob)

def safe_subprocess(target):
    return subprocess.run(["grep", target, "/etc/hosts"], shell=False, check=True)

def safe_json(blob):
    return json.loads(blob)
