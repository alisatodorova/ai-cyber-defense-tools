# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

**Resuming work? Read [STATE.md](STATE.md) first** — it's the up-to-date snapshot of exactly
where things were left off (current status, immediate next step, key facts). See
[HANDOFF.md](HANDOFF.md) for the fuller narrative of what was built and why.

## Purpose

An MCP (Model Context Protocol) server that wraps [Hayabusa](https://github.com/Yamato-Security/hayabusa) — the Windows event log (EVTX) analysis and threat-hunting CLI tool — so that MCP clients (e.g. Claude Code) can run EVTX scans and consume structured results.

## Goals

- Expose a `scan_evtx` MCP tool that runs the Hayabusa CLI against one or more EVTX files, with `min_severity`, `rule_filter`, `output_format` (summary/full), and `max_results` parameters.
- Expose a `get_hayabusa_rules` MCP tool that lists available detection rules (optionally filtered by keyword), so a client can see what rules exist before scanning.
- Return Hayabusa's findings as structured JSON (not raw CLI text output).
- Handle errors gracefully — e.g. missing/invalid EVTX files, Hayabusa not installed or not on PATH, non-zero exit codes, malformed output — and surface them as clear MCP tool errors rather than crashing the server.

## Stack

- Python, using the `mcp` library (MCP Python SDK) to implement the server.
- Hayabusa CLI, expected to be installed locally and invoked as a subprocess (not reimplemented in Python).

## Setup

- Install dependencies: `pip install -r requirements.txt`
- `requirements.txt` pulls in `mcp` and `pyyaml`. Invoking Hayabusa is done via the stdlib `subprocess` module, and its JSONL output is parsed with the stdlib `json` module — no extra HTTP, CSV, or dataframe libraries needed there. `pyyaml` is used only by `get_hayabusa_rules` to read rule metadata (title, level, tags, etc.) out of the YAML rule files under `./hayabusa/rules`. Add a dependency only when a concrete need for it shows up.

## Architecture notes

- The server is a thin wrapper: it shells out to the Hayabusa binary rather than parsing EVTX files itself. Hayabusa does the log parsing and rule matching; this server's job is invocation, output translation (to JSON), filtering, and error handling.
- Since Hayabusa is an external local dependency, prefer failing fast with an actionable error (e.g. "hayabusa not found on PATH") over silently degrading.
- Severity filtering can likely be done via Hayabusa's own CLI flags where available, falling back to post-filtering the JSON output otherwise — check current Hayabusa CLI capabilities before choosing an approach.
