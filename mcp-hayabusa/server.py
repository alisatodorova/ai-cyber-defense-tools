"""MCP server that wraps Hayabusa for EVTX analysis."""

import asyncio
import json
import os
import subprocess
import tempfile
from pathlib import Path

import yaml
import mcp.types as types
from mcp.server import Server
from mcp.server.stdio import stdio_server

server = Server("hayabusa")

SEVERITY_ORDER = ["informational", "low", "medium", "high", "critical"]
OUTPUT_FORMATS = ["summary", "full"]
SUMMARY_FIELDS = ["Timestamp", "RuleTitle", "Level", "Computer", "Channel", "EventID", "RecordID"]
HAYABUSA_DIR = Path(__file__).resolve().parent / "hayabusa"
RULES_DIR = HAYABUSA_DIR / "rules"
SCAN_TIMEOUT_SECONDS = 600

# Populated on first get_hayabusa_rules call; rule files don't change at runtime.
_rules_cache: list[dict] | None = None


class HayabusaNotFoundError(RuntimeError):
    """Raised when the Hayabusa executable can't be located."""


def _find_hayabusa_binary() -> Path:
    exe_name = "hayabusa.exe" if os.name == "nt" else "hayabusa"
    candidate = HAYABUSA_DIR / exe_name
    if candidate.is_file():
        return candidate

    # The official release zip ships a version-suffixed binary name
    # (e.g. hayabusa-3.10.0-win-x64.exe), so fall back to a glob.
    pattern = "hayabusa*.exe" if os.name == "nt" else "hayabusa*"
    matches = sorted(p for p in HAYABUSA_DIR.glob(pattern) if p.is_file())
    if matches:
        return matches[0]

    raise HayabusaNotFoundError(
        f"Hayabusa executable not found in {HAYABUSA_DIR}. "
        "Run scripts/download_hayabusa.py to install it."
    )


def _run_scan_evtx(
    evtx_path: str,
    min_severity: str | None = None,
    rule_filter: str | None = None,
    output_format: str = "summary",
    max_results: int | None = None,
) -> dict:
    path = Path(evtx_path)
    if not path.exists():
        raise FileNotFoundError(f"EVTX path not found: {evtx_path}")

    if min_severity is not None and min_severity not in SEVERITY_ORDER:
        raise ValueError(
            f"Invalid min_severity '{min_severity}'. Must be one of: {', '.join(SEVERITY_ORDER)}"
        )

    if output_format not in OUTPUT_FORMATS:
        raise ValueError(
            f"Invalid output_format '{output_format}'. Must be one of: {', '.join(OUTPUT_FORMATS)}"
        )

    if max_results is not None and (not isinstance(max_results, int) or max_results < 1):
        raise ValueError("max_results must be a positive integer")

    hayabusa_bin = _find_hayabusa_binary()

    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = Path(tmpdir) / "results.jsonl"
        input_flag = "-d" if path.is_dir() else "-f"
        cmd = [
            str(hayabusa_bin),
            "json-timeline",
            input_flag,
            str(path),
            "-o",
            str(output_path),
            "-L",  # JSONL-output: one JSON object per line (plain -o concatenates
                   # pretty-printed objects with no separators, which isn't valid JSON)
            "-b",  # disable-abbreviations: "Level" comes back as "informational" not
                   # "info", matching SEVERITY_ORDER (otherwise info-level findings
                   # get silently dropped by the severity filter below)
            "-w",  # no-wizard: scan for all events/alerts without prompting
            "-q",  # quiet: skip the launch banner
            "-K",  # no-color: keep stdout/stderr clean of ANSI codes
            "-C",  # clobber: overwrite the output file
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=SCAN_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired as e:
            raise RuntimeError(
                f"Hayabusa scan timed out after {SCAN_TIMEOUT_SECONDS}s"
            ) from e
        except OSError as e:
            raise RuntimeError(f"Failed to execute Hayabusa at {hayabusa_bin}: {e}") from e

        if result.returncode != 0:
            raise RuntimeError(
                "Hayabusa exited with code "
                f"{result.returncode}: {result.stderr.strip() or result.stdout.strip()}"
            )

        findings = []
        if output_path.exists() and output_path.stat().st_size > 0:
            # Hayabusa writes a 0-byte file (not "[]") when there are no detections.
            try:
                with output_path.open("r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            findings.append(json.loads(line))
            except json.JSONDecodeError as e:
                raise RuntimeError(f"Failed to parse Hayabusa JSON output: {e}") from e

    if min_severity:
        min_index = SEVERITY_ORDER.index(min_severity)
        findings = [
            f
            for f in findings
            if str(f.get("Level", "")).lower() in SEVERITY_ORDER
            and SEVERITY_ORDER.index(str(f.get("Level", "")).lower()) >= min_index
        ]

    if rule_filter:
        needle = rule_filter.lower()
        findings = [f for f in findings if needle in str(f.get("RuleTitle", "")).lower()]

    total_findings = len(findings)

    truncated = max_results is not None and max_results < total_findings
    if max_results is not None:
        findings = findings[:max_results]

    if output_format == "summary":
        findings = [{k: f.get(k) for k in SUMMARY_FIELDS} for f in findings]

    return {
        "evtx_path": evtx_path,
        "min_severity": min_severity,
        "rule_filter": rule_filter,
        "output_format": output_format,
        "max_results": max_results,
        "total_findings": total_findings,
        "returned_findings": len(findings),
        "truncated": truncated,
        "findings": findings,
    }


def _load_rules() -> list[dict]:
    global _rules_cache
    if _rules_cache is not None:
        return _rules_cache

    rules = []
    for path in RULES_DIR.rglob("*.yml"):
        if ".git" in path.parts or "config" in path.parts:
            continue
        try:
            with path.open("r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except yaml.YAMLError:
            continue
        if not isinstance(data, dict) or "detection" not in data:
            continue
        rules.append(
            {
                "title": data.get("title"),
                "id": data.get("id"),
                "level": data.get("level"),
                "status": data.get("status"),
                "ruletype": data.get("ruletype"),
                "tags": data.get("tags") or [],
                "description": data.get("description"),
                "file": str(path.relative_to(HAYABUSA_DIR)),
            }
        )

    _rules_cache = rules
    return rules


def _get_hayabusa_rules(keyword: str | None = None, max_results: int | None = None) -> dict:
    if not RULES_DIR.is_dir():
        raise HayabusaNotFoundError(
            f"Hayabusa rules directory not found at {RULES_DIR}. "
            "Run scripts/download_hayabusa.py to install it."
        )

    if max_results is not None and (not isinstance(max_results, int) or max_results < 1):
        raise ValueError("max_results must be a positive integer")

    rules = _load_rules()

    if keyword:
        needle = keyword.lower()

        def matches(rule: dict) -> bool:
            haystack = " ".join(
                str(v)
                for v in (
                    rule.get("title"),
                    rule.get("description"),
                    rule.get("id"),
                    " ".join(rule.get("tags") or []),
                )
                if v
            )
            return needle in haystack.lower()

        rules = [r for r in rules if matches(r)]

    total_rules = len(rules)
    truncated = max_results is not None and max_results < total_rules
    if max_results is not None:
        rules = rules[:max_results]

    return {
        "keyword": keyword,
        "max_results": max_results,
        "total_rules": total_rules,
        "returned_rules": len(rules),
        "truncated": truncated,
        "rules": rules,
    }


@server.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="scan_evtx",
            description="Scan an EVTX file (or directory of EVTX files) with Hayabusa.",
            inputSchema={
                "type": "object",
                "properties": {
                    "evtx_path": {
                        "type": "string",
                        "description": "Path to an .evtx file or a directory containing .evtx files.",
                    },
                    "min_severity": {
                        "type": "string",
                        "description": "Optional minimum severity to include.",
                        "enum": SEVERITY_ORDER,
                    },
                    "rule_filter": {
                        "type": "string",
                        "description": "Only include findings whose rule title contains this "
                        "string (case-insensitive), e.g. 'lateral' or 'mimikatz'.",
                    },
                    "output_format": {
                        "type": "string",
                        "description": "'summary' returns a condensed set of fields per finding; "
                        "'full' returns everything Hayabusa reported.",
                        "enum": OUTPUT_FORMATS,
                        "default": "summary",
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum number of findings to return.",
                        "minimum": 1,
                    },
                },
                "required": ["evtx_path"],
            },
        ),
        types.Tool(
            name="get_hayabusa_rules",
            description="List available Hayabusa detection rules, optionally filtered by keyword. "
            "Useful for seeing what rules exist before running scan_evtx.",
            inputSchema={
                "type": "object",
                "properties": {
                    "keyword": {
                        "type": "string",
                        "description": "Only include rules whose title, description, id, or tags "
                        "contain this string (case-insensitive), e.g. 'lateral' or 'mimikatz'.",
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum number of rules to return.",
                        "minimum": 1,
                    },
                },
            },
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    if name == "scan_evtx":
        evtx_path = arguments.get("evtx_path")
        if not evtx_path:
            payload = {"error": "invalid_argument", "message": "evtx_path is required"}
            return [types.TextContent(type="text", text=json.dumps(payload, indent=2))]

        min_severity = arguments.get("min_severity")
        rule_filter = arguments.get("rule_filter")
        output_format = arguments.get("output_format", "summary")
        max_results = arguments.get("max_results")

        try:
            payload = await asyncio.to_thread(
                _run_scan_evtx, evtx_path, min_severity, rule_filter, output_format, max_results
            )
        except HayabusaNotFoundError as e:
            payload = {"error": "hayabusa_not_found", "message": str(e)}
        except FileNotFoundError as e:
            payload = {"error": "file_not_found", "message": str(e)}
        except ValueError as e:
            payload = {"error": "invalid_argument", "message": str(e)}
        except RuntimeError as e:
            payload = {"error": "scan_failed", "message": str(e)}

    elif name == "get_hayabusa_rules":
        keyword = arguments.get("keyword")
        max_results = arguments.get("max_results")

        try:
            payload = await asyncio.to_thread(_get_hayabusa_rules, keyword, max_results)
        except HayabusaNotFoundError as e:
            payload = {"error": "hayabusa_not_found", "message": str(e)}
        except ValueError as e:
            payload = {"error": "invalid_argument", "message": str(e)}

    else:
        raise ValueError(f"Unknown tool: {name}")

    return [types.TextContent(type="text", text=json.dumps(payload, indent=2))]


async def run() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
