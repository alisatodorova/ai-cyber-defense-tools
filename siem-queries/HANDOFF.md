# HANDOFF.md — continuing the work

_Last updated: 2026-07-27_

For the factual snapshot (versions, file status), see `STATE.md`. This doc is the narrative:
what's in flight, what's blocked, and what to do next.

## Immediate blocker

**Splunk is stopped.** The `/query queries/lateral-movement.spl --severity high --assignee
Alisa --case-id CASE-1234` run is queued but cannot execute until Splunk is up. Claude is not
admin and cannot start the service. **User action required:**

```powershell
Start-Service Splunkd
```

(run in an **Administrator** PowerShell), or `& 'C:\Program Files\Splunk\bin\splunk.exe' start`.

Splunkd is set to Automatic but was found Stopped — if it keeps dropping, check
`C:\Program Files\Splunk\var\log\splunk\splunkd.log` for a startup crash.

## Next step (once Splunk is up)

1. Run `queries/lateral-movement.spl` at **`-15y`** (BOTS data is 2018).
2. **Validate it returns data first** — the file's `ADMIN$`/`C$`/`psexec` patterns are
   unvalidated guesses. Earlier keyword probing was interrupted when Splunk went down, so it's
   unknown which lateral-movement indicators actually exist in BOTS v3. Tune the query to real
   data before writing the note (check Sysmon EC1 keywords + `wineventlog:security` 4624
   LogonType 3/10).
3. Write the note to `investigations/` with `severity: high`, `assignee: Alisa`,
   `case_id: CASE-1234`. Likely ATT&CK: T1021.002 (SMB/Admin Shares), T1570 (Lateral Tool
   Transfer), T1569.002 (Service Execution / PsExec).

## Open items / offered but not done

- **Fix the two remaining sample queries** — `powershell-encoded.txt` and
  `scheduled-task-persistence.txt` still use the capitalized sourcetype and rely on extracted
  fields; they need the lowercase sourcetype + inline `rex` treatment (like `whoami.spl`) to
  return data. (Offered; awaiting go-ahead.)
- **Field-extraction decision (unresolved):** install the **Sysmon TA** (clean, CIM-compliant,
  field-based queries) vs. keep **inline `rex`** extraction (zero installs, current approach).
  User hasn't chosen; inline is the working default meanwhile.
- **Retire/repurpose `lsass-access.txt`** — no EventID 10 in BOTS v3, so it can't return data.
- **Stub ATT&CK notes** — offered to generate `T1033.md`/`T1069.md` etc. so `[[backlinks]]`
  resolve to real pages in an Obsidian vault. Not done.
- **Auto-emit HTML per note** — offered to have `/query` also write a standalone shareable
  `.html` beside each `.md`. Not done.

## Recent command evolution (context)

The `/query` command has grown over the session: multi-SIEM backend detection
(Splunk/Elasticsearch/browser) → named metadata flags (`--severity/--assignee/--case-id/
--output-dir`) → fail-fast input validation. Elasticsearch path is written but **untested**
(no ES instance); the JSON-body wrapper needs tightening for complex DSL when a real ES
backend exists.

## Gotchas that will bite (see CLAUDE.md for the full list)

- BOTS data is 2018 → always `-15y`, never rely on `-24h`.
- Sysmon sourcetype is lowercase; matching is case-sensitive.
- No Sysmon TA → raw XML → use inline `rex`.
- PowerShell 5.1 only (no `pwsh`); scripts need the cert-callback + BOM/ASCII treatment.
- Splunk REST is 8089/HTTPS; probe with a TCP connect, not an HTTP GET.
