"""Ground truth: contains 3 command injection findings."""
# expected_findings: SAST-CMDI-001:6, SAST-CMDI-001:7, SAST-CMDI-001:8
import os, subprocess

def run(target):
    os.system("ping " + target)
    os.popen(f"nslookup {target}")
    subprocess.run(f"grep {target} /etc/hosts", shell=True)
