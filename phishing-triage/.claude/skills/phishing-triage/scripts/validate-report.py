#!/usr/bin/env python3
"""Validate a phishing-triage HTML report against the skill's report standards.

Checks the artifact for completeness and — most importantly — defang-safety:

  1. verdict     — a verdict label (Benign / Suspicious / Likely Phish) is present
  2. attack      — an ATT&CK section is present
  3. hash        — the analyzed message's SHA-256 is recorded
  4. no_fanged_url — no live/clickable http(s):// URL leaked into the report
                     (every indicator must be defanged to hxxp://)

Usage:
    python validate-report.py <path-to-report.html>

Prints a JSON report to stdout. Exit 0 if all checks pass, 1 if any fail,
2 on a usage/read error. This validates the report artifact, not the analytic
correctness of the verdict.
"""

import json
import os
import re
import sys

VERDICT_RE = re.compile(r"\b(Benign|Suspicious|Likely Phish)\b")
SHA256_RE = re.compile(r"\b[0-9a-f]{64}\b", re.IGNORECASE)
# A live URL is http(s):// NOT immediately part of a defanged 'hxxp'. Because we
# never emit href="http..." in the report, any raw http(s):// is a defang leak.
FANGED_URL_RE = re.compile(r"https?://", re.IGNORECASE)


def validate(report_path):
    result = {"file": report_path, "valid": False, "checks": {}, "issues": []}

    if not os.path.isfile(report_path):
        result["issues"].append(f"File not found: {report_path}")
        return result

    try:
        with open(report_path, "r", encoding="utf-8") as f:
            html = f.read()
    except OSError as e:
        result["issues"].append(f"Failed to read file: {e}")
        return result

    verdict_ok = bool(VERDICT_RE.search(html))
    result["checks"]["verdict"] = {"passed": verdict_ok}
    if not verdict_ok:
        result["issues"].append("No verdict label (Benign/Suspicious/Likely Phish) found")

    attack_ok = "ATT&CK" in html or "ATT&amp;CK" in html
    result["checks"]["attack"] = {"passed": attack_ok}
    if not attack_ok:
        result["issues"].append("No ATT&CK section found")

    hash_ok = bool(SHA256_RE.search(html))
    result["checks"]["hash"] = {"passed": hash_ok}
    if not hash_ok:
        result["issues"].append("No SHA-256 message hash recorded")

    fanged = FANGED_URL_RE.findall(html)
    no_fanged = not fanged
    result["checks"]["no_fanged_url"] = {"passed": no_fanged, "count": len(fanged)}
    if not no_fanged:
        result["issues"].append(
            f"{len(fanged)} live http(s):// URL(s) leaked into the report — all indicators "
            "must be defanged (hxxp://). This is a safety failure, not a style nit."
        )

    result["valid"] = all(c["passed"] for c in result["checks"].values())
    return result


def main():
    if len(sys.argv) != 2:
        print(json.dumps({"error": "Usage: validate-report.py <path-to-report.html>"}),
              file=sys.stderr)
        sys.exit(2)
    result = validate(sys.argv[1])
    print(json.dumps(result, indent=2))
    sys.exit(0 if result["valid"] else 1)


if __name__ == "__main__":
    main()
