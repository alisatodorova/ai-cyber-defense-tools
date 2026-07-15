# sysmon-parser

A dependency-free Python CLI that extracts and triages the fields analysts actually care about from Sysmon Event ID 1 (Process Creation) XML logs.

> Built as part of [module 2, "Building Your First Security Tool"](https://www.justhacking.com/course/ai-cyber-defense-ops/), from Just Hacking Training's *AI Cyber Defense Ops* course.

## Why this exists

Sysmon XML is verbose and namespaced - pulling out `Image`, `CommandLine`, `ParentImage`, and similar fields by hand (or with generic XML tooling) is tedious, and raw XML isn't something you can easily pipe into `jq`, a SIEM ingest step, or a spreadsheet. `sysmon-parser` extracts the ten fields that matter for process-creation triage and outputs them as JSON, JSONL, or CSV, with filtering and summary statistics built in - turning a raw event log into something you can immediately query or hand off to another tool.

## What it does

Extracts from each Event ID 1 record: `EventID`, `UtcTime`, `Image`, `CommandLine`, `User`, `IntegrityLevel`, `ParentImage`, `ParentCommandLine`, `Computer`, `Hashes`.

Accepts either a single `<Event>` document or an `<Events>`-wrapped file containing many.

**Filtering** (flags AND together; repeated `--command-line` values OR together):

| Flag | Match type |
|---|---|
| `--image` | substring, case-insensitive |
| `--user` | exact |
| `--integrity-level` | exact, case-insensitive |
| `--command-line` (repeatable) | substring, case-insensitive |

**Output formats** (`--format`): `json` (default - mirrors input shape: single object or array), `jsonl` (one object per line, for streaming/piping), `csv` (fixed column order, proper quoting via `csv.DictWriter`).

**Triage mode** (`--stats`): instead of raw events, prints a single summary object - total events, unique processes, unique users, and a breakdown by integrity level. Composes with filters, so you can ask "how many high-integrity events after filtering to PowerShell?" in one call.

## Example usage

```bash
# Parse a single event
python parser.py samples/event1.xml

# Parse a multi-event file → JSON array
python parser.py samples/multi_events.xml

# Only PowerShell processes
python parser.py samples/multi_events.xml --image powershell

# High-integrity events run by a specific user
python parser.py samples/multi_events.xml --integrity-level high --user "CONDEF\Administrator"

# Hunt for obfuscated/encoded PowerShell (dash-prefixed values need the = form)
python parser.py samples/multi_events.xml --command-line encoded --command-line=-enc

# Stream as JSON Lines, or export CSV
python parser.py samples/multi_events.xml --format jsonl
python parser.py samples/multi_events.xml --format csv

# Quick triage: summary stats instead of raw events
python parser.py samples/multi_events.xml --image powershell --stats
```

The included samples model a realistic escalation: `event1.xml` (cmd.exe → whoami.exe), `event2.xml` (cmd.exe → powershell.exe), and `event3.xml` (powershell.exe → powershell.exe with a base64 `-Enc` download cradle - the kind of obfuscated command line the `--command-line` filter is built to catch).

## Skills demonstrated

- Windows process-creation telemetry and what fields actually matter for detection/triage (parent/child process chains, integrity levels, command-line obfuscation patterns like `-enc`)
- Namespaced XML parsing with `xml.etree.ElementTree`, kept dependency-free deliberately
- CLI design: composable filters (AND across fields, OR within repeated flags), multiple output formats for different downstream consumers (human read, `jq`/pipeline, spreadsheet)
- Recognizing and documenting a real argparse limitation (`--command-line=-enc` equals-form requirement for dash-prefixed values) rather than working around it awkwardly

## Known limitations

- Event ID 1 (Process Creation) only - no other Sysmon event types.
- No automated test suite; verified so far via manual runs against the sample files (commands logged in [STATE.md](STATE.md)).
- No packaging/entry point - run directly via `python parser.py`.
- stdout only, no output-to-file option.

See [HANDOFF.md](HANDOFF.md) for the full build narrative and design rationale, and [STATE.md](STATE.md) for the current checkpoint.
