# HANDOFF

## What we built

A single-file Python CLI (`parser.py`) that extracts key fields from Sysmon
Event ID 1 (Process Creation) XML and prints them as JSON.

- Parses Sysmon's namespaced XML using `xml.etree.ElementTree` (stdlib only,
  no dependencies).
- Accepts either a single `<Event>` document or an `<Events>`-wrapped file
  containing multiple `<Event>` children.
- Extracts: `EventID`, `Computer`, `UtcTime`, `Image`, `CommandLine`, `User`,
  `IntegrityLevel`, `ParentImage`, `ParentCommandLine`, `Hashes`.
- Supports filtering the extracted events before output:
  - `--image` — substring match (case-insensitive) on `Image`
  - `--user` — exact match on `User`
  - `--integrity-level` — exact match (case-insensitive) on `IntegrityLevel`
  - `--command-line` — repeatable, substring match (case-insensitive) on
    `CommandLine`; multiple values OR together
  - Different flags AND together.
- Supports `--format` to control output shape: `json` (default), `jsonl` (one
  JSON object per line, for streaming/piping), or `csv` (with headers).
- Supports `--stats` to print summary statistics instead of the events
  themselves: total events, unique processes (Images), unique users, and a
  breakdown of events by `IntegrityLevel`. Applies after filters, ignores
  `--format`. Intended for quick triage of a file before deep analysis.

Four sample files live in `samples/`:
- `event1.xml` — cmd.exe → whoami.exe
- `event2.xml` — cmd.exe → powershell.exe (plain)
- `event3.xml` — powershell.exe → powershell.exe with a base64 `-Enc` download
  cradle (obfuscated PowerShell)
- `multi_events.xml` — events 1–3 combined under a single `<Events>` root, for
  exercising multi-event parsing and filtering

## How to use it

```
python parser.py <path-to-sysmon-event.xml> [filters]
```

Examples:

```
# Parse a single event
python parser.py samples/event1.xml

# Parse a multi-event file (JSON array)
python parser.py samples/multi_events.xml

# Filter: only PowerShell processes
python parser.py samples/multi_events.xml --image powershell

# Filter: only High-integrity events run by a specific user
python parser.py samples/multi_events.xml --integrity-level high --user "CONDEF\Administrator"

# Filter: find obfuscated/encoded PowerShell (note the = form for dash-prefixed values)
python parser.py samples/multi_events.xml --command-line encoded --command-line=-enc

# Output as JSON Lines, for piping/streaming
python parser.py samples/multi_events.xml --format jsonl

# Output as CSV
python parser.py samples/multi_events.xml --format csv

# Triage: summary stats instead of raw events (combines with filters)
python parser.py samples/multi_events.xml --stats
python parser.py samples/multi_events.xml --image powershell --stats
```

Output shape:
- `--format json` (default): `<Event>` input → single JSON object, or `null`
  if it doesn't match the given filters; `<Events>` input → JSON array,
  possibly empty `[]` if nothing matches.
- `--format jsonl`: zero or more JSON object lines (one per matching event,
  regardless of single-`<Event>` vs `<Events>` input).
- `--format csv`: header row always printed, followed by zero or more data
  rows.
- `--stats`: a single JSON object with `TotalEvents`, `UniqueProcessCount`/
  `UniqueProcesses`, `UniqueUserCount`/`UniqueUsers`, and
  `EventsByIntegrityLevel`; overrides `--format`.

## Decisions made and why

- **`xml.etree.ElementTree` over third-party XML libs** — stdlib is sufficient
  for Sysmon's simple, well-formed XML and keeps the project dependency-free.
- **JSON output (object or array depending on input shape)** — mirrors the
  shape of the input rather than always wrapping in an array, so a single-event
  file stays a single object (simplest case for piping into `jq`/other tools).
- **Filtering happens after extraction, on the parsed dict** — not on the XML
  tree — so filter logic stays simple string/equality checks, independent of
  XML/namespace details.
- **Dedicated `--image`/`--user`/`--integrity-level`/`--command-line` flags**
  (over a generic `--filter KEY=VALUE`) — more discoverable via `--help`,
  simpler to argparse, and the fixed set of filterable fields didn't justify a
  generic key/value mechanism.
- **AND across different filters, OR across repeated values of the same
  filter** — matches typical log-filtering expectations (narrow down by
  combining criteria) while still letting `--command-line` express "matches
  any of these known-bad substrings" in one query.
- **`--command-line=-enc` equals-form requirement** — a known argparse
  limitation (a bare `-enc` after a flag looks like another option), not a bug;
  documented in `--help` text rather than worked around.
- **`--format` normalizes to an internal `(events, is_multi)` list before
  branching on output** — jsonl/csv always operate on a flat list of matching
  events regardless of single-`<Event>` vs `<Events>` input, while json mode
  still needs `is_multi` to decide between single-object and array shape.
- **CSV uses a fixed `CSV_FIELDS` column order** (rather than dict insertion
  order used by JSON) so the header is stable and matches the field order
  documented in CLAUDE.md; `csv.DictWriter` handles quoting/escaping of
  commas inside `Hashes`/`ParentCommandLine` automatically.
- **`--stats` computes on the already-filtered event list and ignores
  `--format`** — stats are a single summary object, not a per-event output
  format, so composing it with jsonl/csv wouldn't mean anything; it's meant
  for quick triage of what's in a file before deeper per-event analysis.

## What's left to do

- No automated test suite yet — verification so far has been manual `python
  parser.py ...` runs against the sample files (see CLAUDE.md/STATE.md for the
  commands used).
- No packaging/entry point (`pip install`, `setup.py`/`pyproject.toml`) — run
  directly via `python parser.py`.
- No handling yet for malformed/non-Sysmon XML, or Event IDs other than 1
  (fields specific to other Sysmon event types aren't extracted).
- No output-to-file option — currently stdout only.
