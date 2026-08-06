# HANDOFF — phishing-triage

The build narrative and the decisions behind it, kept as evidence of process (not just the
finished code). For the current-state snapshot, see [STATE.md](STATE.md).

## What this is

The AI Cyber Defense Ops **capstone**: a Phishing Triage Copilot. It was chosen to (a) work
in a domain the course never touched — email — and (b) compose several of the Claude Code
mechanisms the course taught (MCP tool + resource, skill, slash command, hook, persona) into
one tool, while also adding the deliverable type the repo was missing (Module 9's
report/artifact).

## What was built, and why it's shaped this way

1. **`analyze.py` first, as a plain module.** The email parsing + scoring is the real work,
   so it lives in a stdlib-only module with no `mcp` dependency. That keeps it unit-testable
   and CLI-runnable on its own — the same "thin server over real logic" split as
   `mcp-hayabusa`. `server.py` is a wrapper; if you're debugging a wrong verdict, the bug is
   almost certainly in `analyze.py`, not the MCP layer.

2. **Static-only was a hard constraint, not a feature.** The tool analyzes hostile input, so
   the first design decision was "it must be impossible for this to fetch a phishing URL."
   That drove: no network imports in `analyze.py` (with a test asserting it), and a
   `PreToolUse` hook that blocks `WebFetch`/`WebSearch` and network CLIs so the guarantee
   holds at the harness level even against a prompt-injected instruction in an email body.

3. **Scoring is data-driven.** Suspicious TLDs, shorteners, risky extensions, impersonated
   brands, and lure keywords live in `indicators.json` (also the `phishing://indicators`
   resource). The score function reads them; tuning detection is a JSON edit, not a code
   change. This is the Module 4 "knowledge as a resource" lesson applied to scoring.

4. **Samples drove the thresholds.** Three synthetic emails (benign / credential-phish /
   malware-attachment) were written first, then weights/thresholds were tuned until each
   landed on the intended verdict, verified by `test_analyze.py`. Final scores: 0 / 19 / 7,
   against thresholds suspicious≥3, likely-phish≥7.

## Decisions worth remembering

- **`malware-attachment.eml` passes SPF on purpose.** Its verdict is driven by a
  double-extension attachment + a throwaway `.top` sender domain + urgency — demonstrating
  the tool catches a weaponized payload even when authentication passes (a real gap that
  auth-only filters miss). To get it cleanly over the likely-phish line, the double-extension
  signal is weighted +4 (a disguised executable type is a stronger signal than a single auth
  failure) and sender-domain-on-a-high-abuse-TLD adds +2.
- **Defang leaks are treated as a safety bug.** `validate-report.py`'s `no_fanged_url` check
  fails the report on any live `http(s)://` — because the report never emits `href`s, any raw
  URL means an indicator escaped defanging.
- **The attachment is inert HTML.** `malware-attachment.eml`'s payload is a base64 HTML fake
  login form with no script and no network — a realistic HTML-smuggling lure that is
  completely safe to ship and analyze.

## Real-world validation (hardening pass)

After the initial build, the tool was run against two **real** phishing emails from a Bulgarian
`@abv.bg` inbox (`samples/real-world/`, PII scrubbed). Both **passed SPF and DKIM** (attackers
authenticated their own throwaway domains), so they initially scored only `suspicious` — the
auth signal was clean and the structural signals were incomplete. Closing that gap added five
generalizable detectors, each motivated by something the real samples actually did:

- **Sender local-part brand spoof** — `econt-express-bg@asiakas.life` claims Econt in the
  address, not just the display name.
- **Free app-hosting links** (`free_hosting_hosts` in `indicators.json`) — a courier "tracking"
  page on `web.app`. Brands don't host logins/tracking on Firebase/Pages/Workers.
- **Off-brand links** — a brand-impersonating email whose links go to a domain that is neither
  the impersonated brand nor the sender (Google email → `bridgejeanni.com`).
- **1×1 tracking pixels** — remote beacon images.
- **More high-abuse TLDs** — added `.life` (and others) to `suspicious_tlds`.

Both now score `likely-phish` (7 and 10), the synthetic samples are unchanged, and a regression
test asserts the legitimate `econt.com` logo images are **not** mis-flagged (SLD-based lookalike
matching). This is the intended workflow: real inbox traffic surfaces gaps, and detection is
tuned in `indicators.json` + `analyze.py` with a test to lock the behaviour in.

## If you extend it

- More telemetry: parse `.msg` (Outlook) in addition to `.eml`; pull `X-Sender-IP` / ARC.
- Enrichment: cross-reference extracted IOCs against the `mcp-hayabusa` ATT&CK knowledge base
  or a local blocklist resource.
- Port `check-no-detonation.sh` to PowerShell to drop the Git Bash dependency.
- Convert `soc-analyst.md` to a Claude Code output style (the same "Planned" item the
  `personas` module notes).
