"""Demo file with intentional vulnerabilities for AST-SAST defense."""
import os
import sqlite3
import subprocess
import pickle
import yaml
import requests
from flask import Flask, request, render_template_string, Markup, send_file
from jinja2 import Template
from xml.etree import ElementTree
from lxml import etree

app = Flask(__name__)

# 1. Hardcoded secret (SAST-SECRET-001)
API_KEY = "EXAMPLE_FAKE_KEY_DO_NOT_USE_THIS_VALUE_1"
DATABASE_PASSWORD = "EXAMPLE_FAKE_PASSWORD_DO_NOT_USE_THIS_2"

# 2. RCE eval/exec (SAST-RCE-001)
@app.route("/calc")
def calc():
    expr = request.args.get("expr", "")
    return str(eval(expr))

# 3. SQL Injection (SAST-SQLI-001)
@app.route("/user")
def get_user():
    name = request.args.get("name")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
    return str(cursor.fetchone())

# 4. XSS (SAST-XSS-001)
@app.route("/greet")
def greet():
    name = request.args.get("name", "guest")
    return render_template_string("<h1>Hello " + name + "</h1>")

@app.route("/raw")
def raw_html():
    return Markup(request.args.get("html", ""))

# 5. SSTI (SAST-SSTI-001)
@app.route("/render")
def render_dynamic():
    user = request.args["payload"]
    return Template("Hello " + user).render()

# 6. Path Traversal (SAST-PATH-001)
@app.route("/download")
def download():
    filename = request.args["filename"]
    return send_file(os.path.join("/var/data", filename))

# 7. SSRF (SAST-SSRF-001)
@app.route("/fetch")
def fetch():
    url = request.args["url"]
    return requests.get(url).text

# 8. Command Injection (SAST-CMDI-001)
@app.route("/ping")
def ping():
    host = request.args["host"]
    os.system("ping -c 1 " + host)
    subprocess.run(f"nslookup {host}", shell=True)

# 9. Insecure Deserialization (SAST-DESERIAL-001)
@app.route("/load")
def load_payload():
    blob = request.data
    obj = pickle.loads(blob)
    cfg = yaml.load(request.data)
    return str(obj)

# 10. XXE (SAST-XXE-001)
@app.route("/parse")
def parse_xml():
    blob = request.data
    ElementTree.fromstring(blob)
    parser = etree.XMLParser(resolve_entities=True)
    return etree.fromstring(blob, parser)


if __name__ == "__main__":
    app.run(debug=True)
