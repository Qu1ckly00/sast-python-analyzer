"""Ground truth: contains 4 XXE findings."""
# expected_findings: SAST-XXE-001:7, SAST-XXE-001:8, SAST-XXE-001:11, SAST-XXE-001:12
from xml.etree import ElementTree
from lxml import etree

def parse_a(blob):
    ElementTree.fromstring(blob)
    ElementTree.parse(blob)

def parse_b(blob):
    parser = etree.XMLParser(resolve_entities=True)
    return etree.fromstring(blob, parser)
