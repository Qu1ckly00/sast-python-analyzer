"""Ground truth: contains 2 RCE findings."""
# expected_findings: SAST-RCE-001:4, SAST-RCE-001:5
def run(expr, code):
    eval(expr)         # noqa - intentional
    return exec(code)  # noqa - intentional
