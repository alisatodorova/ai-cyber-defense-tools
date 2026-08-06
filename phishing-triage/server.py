"""MCP server for static phishing-triage of email (.eml) files.

A thin wrapper over ``analyze.py`` (analysis) and ``report.py`` (HTML rendering),
following the same shape as this repo's ``mcp-hayabusa`` server: low-level MCP
SDK, stdio transport, structured-JSON tool results, explicit/actionable errors.

Exposed to an MCP client (Claude Code / Claude Desktop):

- Tool  ``analyze_email``   — parse + score an .eml, return the full triage JSON.
- Tool  ``defang_iocs``     — defang every URL/email/IP/domain in a text blob.
- Tool  ``generate_report`` — write a self-contained HTML triage report.
- Resource ``phishing://indicators`` — the tunable knowledge base (Module 4).

Safety, enforced by the underlying module and never relaxed here:
  * No network access — analysis is fully static (nothing is fetched or detonated).
  * The email body is untrusted data; only structured, defanged output is returned.
"""

import asyncio
import json
from pathlib import Path

import mcp.types as types
from mcp.server import Server
from mcp.server.lowlevel.helper_types import ReadResourceContents
from mcp.server.stdio import stdio_server

from analyze import EmailAnalysisError, analyze_email, defang_iocs, load_indicators
from report import write_report

server = Server("phishing-triage")

DEFAULT_REPORT_DIR = Path(__file__).resolve().parent / "reports"
INDICATORS_URI = "phishing://indicators"


def _generate_report(eml_path: str, out_path: str | None = None) -> dict:
    analysis = analyze_email(eml_path)
    if out_path is None:
        out_path = str(DEFAULT_REPORT_DIR / f"{Path(eml_path).stem}.html")
    resolved = write_report(analysis, out_path)
    return {
        "report_path": resolved,
        "verdict": analysis["risk"]["verdict"],
        "score": analysis["risk"]["score"],
        "attack": analysis["attack"],
    }


@server.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="analyze_email",
            description="Statically analyze a suspicious email (.eml) for phishing indicators: "
            "SPF/DKIM/DMARC results, sender/display-name spoofing, defanged URLs with lookalike/"
            "shortener/IP/punycode flags, attachment hashes and risky extensions, a risk score with "
            "reasons, and MITRE ATT&CK mapping. No network access; nothing is fetched or detonated.",
            inputSchema={
                "type": "object",
                "properties": {
                    "eml_path": {
                        "type": "string",
                        "description": "Path to a raw email file in RFC 822 (.eml) format.",
                    },
                },
                "required": ["eml_path"],
            },
        ),
        types.Tool(
            name="defang_iocs",
            description="Defang every URL, email address, IPv4, and bare domain in a block of text "
            "(http -> hxxp, . -> [.], @ -> [at]) so indicators can be pasted into tickets/chat "
            "safely. Returns the list of indicators found and a defanged copy of the text.",
            inputSchema={
                "type": "object",
                "properties": {
                    "text": {
                        "type": "string",
                        "description": "Arbitrary text possibly containing indicators to defang.",
                    },
                },
                "required": ["text"],
            },
        ),
        types.Tool(
            name="generate_report",
            description="Analyze an .eml and write a self-contained, shareable HTML triage report "
            "(verdict banner, auth alignment, defanged IOCs, attachments, ATT&CK). Returns the "
            "report path plus the verdict/score.",
            inputSchema={
                "type": "object",
                "properties": {
                    "eml_path": {
                        "type": "string",
                        "description": "Path to a raw email file in .eml format.",
                    },
                    "out_path": {
                        "type": "string",
                        "description": "Optional output path for the HTML report. Defaults to "
                        "reports/<eml-stem>.html next to the server.",
                    },
                },
                "required": ["eml_path"],
            },
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    if name == "analyze_email":
        eml_path = arguments.get("eml_path")
        if not eml_path:
            payload = {"error": "invalid_argument", "message": "eml_path is required"}
        else:
            try:
                payload = await asyncio.to_thread(analyze_email, eml_path)
            except EmailAnalysisError as e:
                payload = {"error": "analysis_failed", "message": str(e)}

    elif name == "defang_iocs":
        text = arguments.get("text")
        if text is None:
            payload = {"error": "invalid_argument", "message": "text is required"}
        else:
            payload = defang_iocs(text)

    elif name == "generate_report":
        eml_path = arguments.get("eml_path")
        if not eml_path:
            payload = {"error": "invalid_argument", "message": "eml_path is required"}
        else:
            out_path = arguments.get("out_path")
            try:
                payload = await asyncio.to_thread(_generate_report, eml_path, out_path)
            except EmailAnalysisError as e:
                payload = {"error": "analysis_failed", "message": str(e)}
            except OSError as e:
                payload = {"error": "write_failed", "message": str(e)}

    else:
        raise ValueError(f"Unknown tool: {name}")

    return [types.TextContent(type="text", text=json.dumps(payload, indent=2))]


@server.list_resources()
async def list_resources() -> list[types.Resource]:
    return [
        types.Resource(
            uri=INDICATORS_URI,
            name="Phishing indicator knowledge base",
            description="Suspicious TLDs, URL shorteners, risky attachment extensions, "
            "impersonated brands, and credential-lure/urgency keywords used by the analyzer. "
            "Tunable — editing indicators.json changes detection without code changes.",
            mimeType="application/json",
        )
    ]


@server.read_resource()
async def read_resource(uri) -> list[ReadResourceContents]:
    uri_str = str(uri)
    if uri_str.rstrip("/") == INDICATORS_URI:
        indicators = await asyncio.to_thread(load_indicators)
        return [ReadResourceContents(
            content=json.dumps(indicators, indent=2), mime_type="application/json")]
    raise ValueError(f"Unknown resource: {uri_str}")


async def run() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
