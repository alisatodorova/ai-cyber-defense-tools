# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

When resuming work in this repository, read `HANDOFF.md` (what was built, how to use it,
decisions made and why, what's left to do) and `STATE.md` (terse checkpoint of current
working state, last-verified commands) before starting new work.

## Project overview

This is a Sysmon XML parser project. The goal is to build a Python tool that extracts key
fields from Sysmon Event ID 1 (Process Creation) events out of Sysmon XML event logs.

Fields to extract from each Event ID 1 record:

- `EventID`
- `UtcTime`
- `Image` (process path)
- `CommandLine`
- `User`
- `IntegrityLevel`
- `ParentImage`
- `ParentCommandLine`
- `Computer`
- `Hashes`

Output format: JSON — either one JSON object per event, or a JSON array when parsing
multiple events from a single input.

## Architecture

- **`parser.py`** is the entire implementation (single file, no dependencies beyond
  the Python standard library).
- **XML parsing**: uses `xml.etree.ElementTree`. The Sysmon namespace
  (`http://schemas.microsoft.com/win/2004/08/events/event`) is registered once as `NS`
  and passed to every `find`/`findall` call — don't forget it when adding new lookups,
  or they'll silently return `None`/empty.
- **Input shape handling**: `parse_file()` accepts either a lone `<Event>` root or an
  `<Events>` wrapper containing multiple `<Event>` children (see
  `samples/multi_events.xml`). The root tag determines both how parsing branches and
  the output shape: a single `<Event>` input yields one JSON object (or `null` if
  filtered out), an `<Events>` input always yields a JSON array (possibly empty).
- **Field extraction**: `parse_event()` reads `EventID`/`Computer` from `<System>`, then
  builds a `Name -> text` dict from every `<Data>` element under `<EventData>` and pulls
  the fields listed in `FIELDS` out of it. Adding a new field to extract just means
  appending its `Data/@Name` value to `FIELDS`.
- **Filtering**: `matches_filters(event, args)` runs after extraction, against the
  already-parsed field dict (not the XML tree). Supported flags:
  - `--image` — substring match (case-insensitive) against `Image`
  - `--user` — exact match against `User`
  - `--integrity-level` — exact match against `IntegrityLevel` (case-insensitive)
  - `--command-line` — repeatable; substring match (case-insensitive) against
    `CommandLine`, values OR'd together
  - Different flags AND together (an event must satisfy every flag provided); multiple
    values passed to the *same* repeatable flag (`--command-line`) OR together. A flag
    that isn't passed imposes no constraint.
  - Values starting with `-` (e.g. `-enc`) need the `--command-line=-enc` equals form,
    since argparse would otherwise treat them as another flag.
