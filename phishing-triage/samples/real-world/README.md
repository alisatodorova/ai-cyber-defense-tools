# Real-world samples

Two **real phishing emails** received on a Bulgarian `@abv.bg` mailbox, kept as evidence that
the tool works on genuine, in-the-wild phish (not just synthetic fixtures) — and specifically
on **non-English** mail.

## Sanitization

The recipient's personal information has been scrubbed: the mailbox local part was replaced
with `recipient` (so the address reads `recipient@abv.bg`) throughout the headers and bodies.
No other content was altered — the attacker's infrastructure (sender domains, links, headers,
DKIM signatures) is left intact as IOCs. A test (`test_analyze.py::check_real_samples_pii_scrubbed`)
asserts the PII does not reappear. The attacker-controlled URLs in these files are live-in-the-wild
phishing links — the tooling only ever handles them **statically and defanged**; do not visit them.

## The samples

| File | Lure | Verdict | Why it's caught (it passes SPF **and** DKIM) |
|---|---|---|---|
| `google-cloud-storage-phish.eml` | "Google Cloud storage expiring — save 90%" (Bulgarian) | `likely-phish` (7) | Display name "Google" from `flatley.yadel.org`; links to an unrelated domain (`bridgejeanni.com`), not Google or the sender; a 1×1 tracking pixel; urgency wording. |
| `econt-parcel-phish.eml` | "IMPORTANT: action needed to receive your parcel" — Econt courier (Bulgarian) | `likely-phish` (10) | Sender `econt-express-bg@asiakas.life` claims Econt but the domain doesn't; `.life` high-abuse TLD; a lookalike link on `web.app` free hosting. The **real** `econt.com` logo images are correctly left unflagged. |

## Why they matter

Both emails **pass SPF and DKIM** — the attackers authenticated their own throwaway domains.
An auth-only filter waves them through. They're a concrete demonstration that the interesting
detection is in *brand alignment, link reputation, and behaviour*, not just authentication —
and analyzing them is what drove several of the tool's detection signals (sender local-part
brand spoofing, off-brand links, free-hosting links, high-abuse TLDs, tracking pixels).
