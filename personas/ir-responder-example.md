# Incident Response Persona — Example Session

## Command

```
claude --append-system-prompt-file ~/.claude/personas/ir-responder.md
```

## Question

I just got called onto a ticket. An EDR alert fired on WIN-HR-03 for suspected
Cobalt Strike beaconing to 185.243.x.x at 09:14 UTC. What do you want me to
collect first, and what questions should I be trying to answer?

## Output

**TL;DR (exec):** EDR flagged suspected Cobalt Strike C2 beaconing from WIN-HR-03 to an external IP at 09:14 UTC — this is unconfirmed (alert only, no corroborating evidence yet); next step is read-only evidence collection, not remediation.

**Fact/Inference so far:**

| Time (UTC) | Event | Source | Fact/Inference |
|------------|-------|--------|----------------|
| 09:14:00Z | EDR alert: suspected CS beaconing, WIN-HR-03 → 185.243.x.x | EDR console | **Fact** (alert fired) |
| — | Traffic is actual Cobalt Strike C2 | — | **Inference** — EDR heuristic, not yet confirmed by packet/process evidence |

## What to collect first (read-only, in priority order)

1. **EDR process tree around 09:14Z** — the process that generated the network connection, its parent chain, command line, and hash. This tells you initial access vector and whether it's a live implant or a false positive.
   - `wevtutil epl Microsoft-Windows-Sysmon/Operational sysmon_export.evtx` (if Sysmon present) rather than querying live and risking gaps.
   - From EDR: export process, network, and file-creation events for WIN-HR-03, window **08:00Z–10:00Z** (pad ±1hr around the alert to catch staging/beacon setup).

2. **Full network connection history for WIN-HR-03** to `185.243.x.x` — first-seen time, port(s), byte counts, beacon interval/jitter (regular intervals are a strong CS indicator vs. one-off).

3. **Memory-resident indicators, if EDR supports live query without host modification** — injected threads, unsigned/unbacked executable memory regions (classic CS reflective-loader behavior). Do **not** trigger a memory dump that requires killing/suspending the process yet — flag it as an option, don't execute.

4. **Parent authentication context** — who was logged onto WIN-HR-03 at/before 09:14Z (interactive vs. service), and whether that account has since been used elsewhere (lateral movement check).

5. **File system artifacts** — any newly dropped/modified files in the timeframe (staging directories, dropped binaries, LNK/scheduled task persistence). Read via forensic export, not live disk browsing on the host.

6. **DNS/proxy logs** — was `185.243.x.x` resolved via a domain, or hit directly by IP? Domain would give you a pivot for retro-hunting across the environment.

## Questions to answer

- **Is this a confirmed beacon or a heuristic false positive?** — process tree + injected memory region evidence is what confirms it.
- **What's the initial access vector?** — phishing attachment, exploited service, valid account, etc. (maps to ATT&CK Initial Access tactics — need the parent process chain to know which).
- **How long has this been active?** — first-seen connection to `185.243.x.x` may predate the 09:14Z alert; EDR detection time ≠ compromise time.
- **Has beaconing occurred to any other hosts or IPs from WIN-HR-03, or has the same IP been contacted by any other host in the environment?** — scope question, answers whether this is isolated or environment-wide.
- **Is WIN-HR-03 a privileged/Tier-0 adjacent host** (e.g., does an HR admin or domain-joined service account regularly log in here)? Shapes urgency.
- **Has there been any lateral movement attempt from this host** (SMB, WinRM, RDP, new scheduled tasks on other hosts) since 09:14Z?

**IOCs (initial):**

| Indicator | Type | First Seen | Source |
|-----------|------|------------|--------|
| 185.243.x.x | IP | 09:14:00Z (alert time — not necessarily first contact) | EDR alert |
| WIN-HR-03 | Host | 09:14:00Z | EDR alert |

**Open questions / gaps:** No process, memory, or auth evidence yet — everything above is what's needed to move this from "alert" to "confirmed incident." I don't have the full /24 or domain for `185.243.x.x`, EDR platform in use, or Sysmon/logging coverage on this host — knowing those will shape which queries I write next.

**Recommended next steps:** Pull items 1–2 above first (process tree + connection history) since they'll confirm or kill the hypothesis fastest. Paste the process tree and connection log excerpt when you have them and I'll build out the timeline and IOC table from there.
