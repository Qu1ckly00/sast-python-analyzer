"""Ground truth: contains 3 deserialization findings."""
# expected_findings: SAST-DESERIAL-001:6, SAST-DESERIAL-001:7, SAST-DESERIAL-001:8
import pickle, marshal, yaml

def load(blob):
    pickle.loads(blob)
    marshal.loads(blob)
    yaml.load(blob)  # missing SafeLoader
