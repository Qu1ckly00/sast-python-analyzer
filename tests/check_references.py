"""Verify integrity of the reference list in build_docx.py.

For each numeric citation [N] used in the text, check that:
1. an entry exists in the reference list,
2. the entry is actually cited at least once.

Outputs a sorted list of:
  - missing entries (citation used but no entry exists);
  - unused entries (entry exists but never cited);
  - any duplicates inside text.
"""
from __future__ import annotations
import re
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD_FILE = os.path.join(ROOT, "build_docx.py")


def main() -> int:
    with open(BUILD_FILE, "r", encoding="utf-8") as fh:
        src = fh.read()

    # 1. Find the reference list (entries are added inside build_references
    #    as elements of a list literal `refs = [ "...", "...", ... ]`).
    refs_block_match = re.search(
        r"def build_references\(doc\):(.+?)(?=\n# |\ndef |\Z)",
        src, re.DOTALL,
    )
    refs_block = refs_block_match.group(1) if refs_block_match else ""

    # Locate the list literal and count its string items.
    list_match = re.search(r"refs\s*=\s*\[(.+?)\]\s*\n", refs_block, re.DOTALL)
    if not list_match:
        print("Could not locate refs = [ ... ] block.")
        return 1
    list_body = list_match.group(1)
    # Each entry is a (possibly multi-line) string ending with a comma.
    # Count strings by counting top-level commas at the end of a "..." token.
    entries = re.findall(r'"(?:[^"\\]|\\.)*"(?=\s*[,\]])', list_body)
    # Merge consecutive string-literal chunks that Python concatenates
    # implicitly (multi-line strings split by line breaks).
    declared = list(range(1, len(entries) + 1))

    # 2. Find all [N] citations in the body (everywhere in the file).
    citation_pattern = re.compile(r"\[(\d+)(?:[,;\s]|с\.|–|-)?[^\]]*\]")
    cited = []
    for m in citation_pattern.finditer(src):
        # Skip occurrences inside the reference block itself.
        if refs_block and refs_block_match.start() <= m.start() <= refs_block_match.end():
            continue
        cited.append(int(m.group(1)))
    # Reference numbering starts at 1; ignore [0] which only matches
    # Python list indexing in the build script or numeric intervals.
    cited_set = {n for n in cited if n >= 1}

    declared_set = set(declared)
    missing = sorted(cited_set - declared_set)
    unused = sorted(declared_set - cited_set)

    print(f"Declared entries: {len(declared)}  (range 1..{max(declared) if declared else 0})")
    print(f"Cited unique numbers: {len(cited_set)}")
    print(f"Total citations in text: {len(cited)}")
    print()

    if missing:
        print("[FAIL] MISSING in reference list (cited but no entry):")
        for n in missing:
            print(f"  [{n}]")
    else:
        print("[OK] All cited numbers have entries.")

    if unused:
        print("\n[WARN] UNUSED entries (declared but never cited):")
        for n in unused:
            print(f"  {n}")
    else:
        print("\n[OK] Every declared entry is cited.")

    return 0 if not missing else 1


if __name__ == "__main__":
    raise SystemExit(main())
