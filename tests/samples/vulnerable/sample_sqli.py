"""Ground truth: contains 3 SQLi findings."""
# expected_findings: SAST-SQLI-001:6, SAST-SQLI-001:7, SAST-SQLI-001:8
import sqlite3

def lookup(cursor, name):
    cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
    cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")
    cursor.execute("SELECT * FROM users WHERE name = '{}'".format(name))
