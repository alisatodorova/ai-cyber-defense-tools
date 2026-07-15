# STATE

Snapshot of working state as of 2026-07-13. See HANDOFF.md for the fuller
narrative (what/why); this file is the terse "where things stand" checkpoint.

## Files

- `parser.py` — complete for current scope: XML parsing (single `<Event>` or
  `<Events>`-wrapped), field extraction, filtering (`--image`, `--user`,
  `--integrity-level`, `--command-line`), output format selection (`--format
  json|jsonl|csv`), and triage stats (`--stats`).
- `samples/event1.xml` — cmd.exe → whoami.exe
- `samples/event2.xml` — cmd.exe → powershell.exe (plain)
- `samples/event3.xml` — powershell.exe → powershell.exe, base64 `-Enc`
  download cradle
- `samples/multi_events.xml` — events 1–3 wrapped in `<Events>`
- `CLAUDE.md` — has project overview + architecture section (parsing,
  input/output shape, filtering rules)
- `HANDOFF.md` — full handoff doc (what/how/decisions/todo)

## Last verified behavior

All commands below were run and produced the expected output in the current
session:

```
python parser.py samples/event1.xml
python parser.py samples/multi_events.xml
python parser.py samples/multi_events.xml --image powershell
python parser.py samples/multi_events.xml --integrity-level high
python parser.py samples/multi_events.xml --image powershell --user "CONDEF\Administrator"
python parser.py samples/event1.xml --image cmd            # -> null
python parser.py samples/event1.xml --image whoami         # -> single object
python parser.py samples/multi_events.xml --command-line=-enc
python parser.py samples/multi_events.xml --command-line encoded --command-line=-enc
python parser.py samples/multi_events.xml --command-line=-enc --integrity-level high
python parser.py samples/multi_events.xml --format json
python parser.py samples/multi_events.xml --format jsonl
python parser.py samples/multi_events.xml --format csv
python parser.py samples/multi_events.xml --command-line=-enc --format csv
python parser.py samples/multi_events.xml --stats
python parser.py samples/multi_events.xml --image powershell --stats
```

## Not yet started

- Automated tests (pytest or similar)
- Packaging (setup.py/pyproject.toml, console entry point)
- Handling for non-Event-ID-1 events or malformed input
- Output-to-file option

## Resuming work

Read `CLAUDE.md` first (architecture), then `HANDOFF.md` for full context and
rationale, then this file for the latest checkpoint before picking up new
work.
