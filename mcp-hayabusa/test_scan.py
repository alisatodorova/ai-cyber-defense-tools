"""Simple manual test: call the scan_evtx tool directly against a sample EVTX file.

Usage:
    python test_scan.py
"""

import asyncio
import json
from pathlib import Path

from server import call_tool

SAMPLE_EVTX = Path(__file__).resolve().parent / "test_data" / "UACME_59_Sysmon.evtx"


async def main() -> None:
    if not SAMPLE_EVTX.exists():
        raise SystemExit(f"Sample EVTX file not found: {SAMPLE_EVTX}")

    print(f"Scanning {SAMPLE_EVTX} (min_severity=informational) ...")
    result = await call_tool(
        "scan_evtx",
        {"evtx_path": str(SAMPLE_EVTX), "min_severity": "informational"},
    )
    payload = json.loads(result[0].text)

    if "error" in payload:
        print(f"Scan failed: {payload['error']} - {payload['message']}")
        return

    print(f"Total findings: {payload['total_findings']}")
    for finding in payload["findings"]:
        print(f"  - [{finding.get('Level')}] {finding.get('RuleTitle')} (EventID {finding.get('EventID')})")


if __name__ == "__main__":
    asyncio.run(main())
