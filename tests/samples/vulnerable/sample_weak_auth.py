"""Ground truth: contains 3 weak-authentication findings."""
# expected_findings: SAST-AUTH-001:7, SAST-AUTH-001:12, SAST-AUTH-001:18
import hashlib

def login_a(user, password):
    # Hardcoded credential comparison
    if password == "admin123":
        return True
    return False

def login_b(user, pwd):
    if "secret" == pwd:               # literal on the left
        return True
    return False

def store_password(password):
    # Weak hash used for password storage
    return hashlib.md5(password.encode()).hexdigest()
