# phishing-triage — Phishing Triage Copilot

> **Course capstone.** A static, offline phishing-triage tool for a domain the [**AI Cyber Defense Ops**](https://www.justhacking.com/course/ai-cyber-defense-ops/) course never covered — email — that composes *five* of the Claude Code
> extension mechanisms the course taught into one cohesive workflow.

Point it at a suspicious `.eml` and it parses the headers, checks SPF/DKIM/DMARC and sender
alignment, extracts and **defangs** every URL/IP/attachment, scores the message, maps it to
MITRE ATT&CK, and writes a shareable HTML triage report — **without ever fetching a URL or
opening an attachment**. Analysis is 100% static; nothing is detonated.

## Why this is the capstone

The rest of this repo demonstrates each Claude Code mechanism in isolation, on endpoint and
cloud telemetry. This capstone does two things those don't:

1. **New domain.** Email/phishing, SPF-DKIM-DMARC alignment, IOC defanging, and static
   URL/attachment triage appear nowhere in the course.
2. **Composition.** It wires the mechanisms together around a single tool, and adds the one
   deliverable type the repo was missing (an interactive **report/artifact**):

| Mechanism | In this project |
|---|---|
| **MCP server** (structured-JSON tools) | `server.py` — `analyze_email`, `defang_iocs`, `generate_report` |
| **MCP resource** (knowledge base) | `phishing://indicators` ← the tunable `indicators.json` |
| **Skill** (codified methodology) | `.claude/skills/phishing-triage/` + `validate-report.py` |
| **Slash command** (repeatable workflow) | `/triage-email <email.eml>` |
| **Hook** (harness-enforced guardrail) | `PreToolUse` block on any URL fetch / network CLI |
| **Persona** (system prompt) | `personas/soc-analyst.md` — verdict-first L1 triage mindset |
| **Report / artifact** | self-contained, theme-aware HTML triage report |

## What it detects

- **Authentication:** SPF / DKIM / DMARC verdicts parsed from `Authentication-Results`.
- **Sender spoofing:** From vs Reply-To vs Return-Path domain mismatches; brand impersonation
  in the display name *or* the address local part (a "PayPal"/"Econt" identity from an
  unrelated domain).
- **Malicious links:** brand-lookalike hosts, URL shorteners, raw-IP links, punycode/IDN
  homographs, high-abuse TLDs, free app-hosting (`web.app`/`pages.dev`/…), credential-lure
  paths (`/login`, `/verify`, `/account`), a brand-impersonating email that links **off-brand**
  (to neither the impersonated brand nor the sender's own domain), and 1×1 tracking pixels.
- **Weaponized attachments:** risky extensions (`.html .iso .lnk .js .hta .scr .exe .docm …`),
  double extensions (`invoice.pdf.html`), plus SHA-256 hashes for blocklisting.
- **Social engineering:** urgency / account-suspension pressure language.

Each signal carries a weight; the total maps to a verdict — `benign` / `suspicious` /
`likely-phish` — with the specific reasons shown. Findings map to ATT&CK **T1566.001/.002**,
**T1204.001/.002**, and **T1036**.

## The report

`generate_report` writes a single self-contained `.html` (inline CSS/JS, no external
requests, light/dark aware): a color-coded verdict banner, the weighted reason list, an
auth-alignment table, defanged-IOC and attachment tables (with copy buttons and hashes), the
Received-hop delivery path, and ATT&CK chips. Three are committed under [`reports/`](reports/)
— open [`reports/credential-phish.html`](reports/credential-phish.html) in a browser.

## Design decisions (the security is the point)

- **Static-only, no detonation.** `analyze.py` imports no `socket`/`urllib`/`requests` — a
  unit test asserts this. A `PreToolUse` hook (`scripts/check-no-detonation.sh`) blocks
  `WebFetch`/`WebSearch` and network CLIs (`curl`/`wget`/`nslookup`/…) at the harness level,
  so the "never fetch a phishing URL" rule holds regardless of what any instruction — or the
  email body — tries to make the agent do.
- **The email is untrusted data.** A phishing body can carry text aimed at an LLM
  (prompt injection). Every layer — engine, skill, command, persona — treats email content
  as data to analyze, never as instructions, and flags manipulation attempts as findings.
- **Defang everything.** No live indicator ever reaches output; `validate-report.py` fails a
  report if a clickable `http(s)://` URL leaked in.
- **Thin MCP wrapper.** All logic lives in `analyze.py` / `report.py` so it's testable
  without the MCP SDK — the same pattern as this repo's `mcp-hayabusa` server.
- **Detection is data, not code.** Suspicious TLDs, shorteners, risky extensions, and
  impersonated brands live in `indicators.json` (also exposed as `phishing://indicators`) —
  tune coverage without touching Python.

## Usage

```bash
pip install -r requirements.txt          # only dependency: mcp (analysis itself is stdlib)

python analyze.py samples/credential-phish.eml                 # triage JSON to stdout
python report.py  samples/credential-phish.eml out.html        # write an HTML report
python test_analyze.py                                         # offline tests over the samples
```

As an MCP server (registered in `.mcp.json` as `phishing-triage`): launch Claude Code from
this folder, confirm with `/mcp`, then:

```
/triage-email samples/credential-phish.eml
```

As a persona:

```bash
claude --append-system-prompt-file personas/soc-analyst.md
```

## Samples

All synthetic and inert — safe to analyze, no real malware or live infrastructure:

| File | Verdict | Why |
|---|---|---|
| `samples/benign-newsletter.eml` | `benign` (0) | Authenticated, aligned, clean links — proves low false-positive. |
| `samples/credential-phish.eml` | `likely-phish` (19) | SPF/DKIM/DMARC fail, PayPal display-name spoof from a lookalike domain, credential-lure link. |
| `samples/malware-attachment.eml` | `likely-phish` (7) | Authenticated-but-throwaway `.top` sender, `Invoice_2026.pdf.html` double-extension attachment. |
| `samples/credential-phish-bg.eml` | `likely-phish` (20) | Bulgarian (Cyrillic) ДСК Банк credential phish — MIME-encoded subject, `.top` lookalike bank domain, Cyrillic urgency wording. |

## Non-English email (e.g. Bulgarian)

Most of the detection is **language-agnostic** and works on any email out of the box:
authentication (SPF/DKIM/DMARC), sender/display-name spoofing, URL analysis (lookalike,
shortener, raw-IP, punycode, high-abuse TLD), attachment risk, and ATT&CK mapping don't
depend on the body language. MIME-encoded Cyrillic (and other) headers are decoded, and
UTF-8/windows-1251 bodies are handled by the parser.

The only language-sensitive part is the **urgency / credential-lure keyword** scoring — so
`indicators.json` ships **Bulgarian keywords and Bulgarian bank/brand names** (ДСК, УниКредит,
Пощенска банка, Fibank, Vivacom, Yettel, Econt, Speedy, …) alongside the English set. Add
your language's phrasing to that file — no code change — and the social-engineering signal
works there too. Lookalike matching is TLD-agnostic (SLD-based), so it correctly distinguishes
the real `dskbank.bg` from a `dskbank-online.top` lookalike.

## Real-world validation

[`samples/real-world/`](samples/real-world/) holds two **actual phishing emails** received on a
Bulgarian `@abv.bg` mailbox (recipient PII scrubbed), with their generated reports in
[`reports/`](reports/). Both **pass SPF and DKIM** — the attackers authenticated their own
throwaway domains — yet both are correctly rated `likely-phish`, caught on brand alignment and
link behaviour rather than authentication:

- **Google Cloud lookalike** → a "Google" display name from `flatley.yadel.org`, links to an
  unrelated `bridgejeanni.com`, and a 1×1 tracking pixel.
- **Econt courier lookalike** → sender `econt-express-bg@asiakas.life` (claims Econt, `.life`
  domain) with a lookalike link on `web.app` free hosting — while the email's real `econt.com`
  logo images are correctly left unflagged.

Triaging these live samples is what drove several of the detection signals above (sender
local-part brand spoofing, off-brand links, free-hosting links, high-abuse TLDs, tracking
pixels) — a small worked example of hardening detection against real inbox traffic.

## Skills demonstrated

**Security fundamentals:** email header / authentication analysis (SPF·DKIM·DMARC), sender
and display-name spoof detection, phishing IOC extraction and defanging, malicious-URL and
weaponized-attachment triage, MITRE ATT&CK mapping, and verdict/escalation discipline.

**AI/agentic engineering:** composing an MCP server, resource, skill, slash command, hook,
and persona into one workflow; keeping analysis logic testable behind a thin MCP wrapper;
treating an untrusted document (and the model's own tool surface) as an attack boundary —
enforcing "never detonate" as a harness-level guardrail rather than a hopeful instruction;
and driving detection from an editable knowledge base instead of hardcoded logic.

## Known limitations

- **Verdict is a triage prior, not ground truth.** Weights are heuristics tuned against the
  three bundled samples; a real deployment would calibrate them against labeled corpora.
- **SPF/DKIM/DMARC are read from `Authentication-Results`** as written by the receiving MTA —
  the tool trusts that header, it does not re-verify signatures or SPF records (that would
  require the very network access this tool refuses).
- **URL/attachment analysis is static.** It flags *indicators*; it does not unpack archives,
  follow redirects, or render HTML. Dynamic detonation is intentionally out of scope.
- The `check-no-detonation.sh` hook is **Bash + jq** (Git Bash), like the `detection-workflow`
  module — no native PowerShell port yet.
