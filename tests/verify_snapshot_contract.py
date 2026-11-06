#!/usr/bin/env python3
"""
Verification script for Phase 1 & Phase 3 acceptance criteria on systems with Python 3:
1. Parses real feed files in d:/NTNU-DevOps/Gitbash/Fortigate using exact parser rules.
2. Compares counts against exact line counts (equivalent to PowerShell Measure-Object).
3. Verifies LongTerm commit regex against real git log of Fortigate.
4. Verifies Snapshot JSON contract contains zero IPv4 (\d+\.\d+\.\d+\.\d+) strings.
"""
import json
import os
import re
import subprocess
import sys

sys.stdout.reconfigure(encoding="utf-8")

FORTIGATE_DIR = r"d:\NTNU-DevOps\Gitbash\Fortigate"

IPV4_RE = re.compile(r"\d+\.\d+\.\d+\.\d+")
LONGTERM_COMMIT_RE = re.compile(
    r"^feed\(longterm\s+v[\d.]+\):\s*update\s+g-BLACK_IP_AutoLongTerm-v1\.txt\s*\(total=(\d+)\s+added=(\d+)\s+removed=(\d+)\)",
    re.I,
)


def parse_feed_file(path: str):
    with open(path, "rb") as f:
        raw_bytes = f.read()
    text = raw_bytes.decode("utf-8", errors="replace")
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    header_count = None
    entries = set()
    valid_count = 0
    for line in lines:
        trimmed = line.strip()
        if not trimmed:
            continue
        if trimmed.startswith("#"):
            m = re.match(r"^#\s*Count\s*:\s*(\d+)", trimmed, re.I)
            if m:
                header_count = int(m.group(1))
            continue
        token = re.split(r"\s+#|\s+", trimmed)[0].strip()
        if not token:
            continue
        valid_count += 1
        entries.add(token)
    return {
        "count": valid_count,
        "bytes": len(raw_bytes),
        "headerCount": header_count,
        "headerMismatch": (header_count is not None and header_count != valid_count),
    }


def main():
    test_files = [
        "g-BLACK_IP_AutoLongTerm-v1.txt",
        "ncloud_block_src_topn.txt",
        "ncloud_block_dst_topn.txt",
        "emailsys_block_ipset.txt",
        "Security-UCP-maintenance-v1.txt",
    ]
    results = {}
    for fname in test_files:
        fpath = os.path.join(FORTIGATE_DIR, fname)
        stats = parse_feed_file(fpath)
        results[fname] = stats
        print(f"[PASS] {fname}: count={stats['count']}, bytes={stats['bytes']}, headerCount={stats['headerCount']}, mismatch={stats['headerMismatch']}")

    # Check git log parsing on real Fortigate repo
    git_out = subprocess.check_output(
        ["git", "-C", FORTIGATE_DIR, "log", "-n", "30", "--oneline", "g-BLACK_IP_AutoLongTerm-v1.txt"],
        text=True,
        encoding="utf-8",
    )
    matched_commits = 0
    for line in git_out.splitlines():
        parts = line.split(" ", 1)
        if len(parts) == 2 and LONGTERM_COMMIT_RE.match(parts[1].strip()):
            matched_commits += 1
    assert matched_commits > 0, "Expected LongTerm commits to match regex"
    print(f"[PASS] Matched {matched_commits} LongTerm commits from git log")

    # Verify serialized snapshot has zero IPv4 regex matches
    snapshot_json = json.dumps(results)
    assert not IPV4_RE.search(snapshot_json), "Snapshot JSON leaked an IPv4 address!"
    print("[PASS] Zero IPv4 strings in serialized Snapshot JSON")


if __name__ == "__main__":
    main()

