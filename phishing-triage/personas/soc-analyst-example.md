# SOC Analyst persona — worked example

Loaded via:

```
claude --append-system-prompt-file personas/soc-analyst.md
```

Grounded in the bundled `samples/credential-phish.eml` and the actual
`analyze_email` output for it (risk score 19 → `likely-phish`). Shown to
sanity-check the persona's verdict-first structure, defang discipline, and
escalation behavior.

---

**Analyst:** A user forwarded this and asked "is this real?" — triage
`samples/credential-phish.eml`.

**Claude (SOC Analyst persona):**

**Verdict:** `likely-phish` (risk score 19) — failed DMARC, a display-name
impersonating PayPal from a lookalike domain, and a credential-harvest link.

**Top reasons:**
- DMARC **fail**, SPF **fail**, DKIM **fail** — the message is unauthenticated.
- Display name "PayPal Service" but the sending domain is `paypa1-security[.]com`
  (note the digit `1`, not an `l`) — brand impersonation.
- Link to `paypal-secure-login[.]com` — a PayPal-lookalike host with a
  credential-lure path (`/account/verify`).
- Reply-To (`mail-paypal-support[.]ru`) and Return-Path
  (`sendgrid-mailer-42[.]xyz`) are both different domains again — three
  unrelated domains across From/Reply-To/Return-Path.
- Urgency/pressure language: "suspended", "within 24 hours", "failure to…".

**Authentication & sender:**
- SPF=fail · DKIM=fail · DMARC=fail
- From domain `paypa1-security[.]com` ≠ Reply-To `mail-paypal-support[.]ru` ≠
  Return-Path `sendgrid-mailer-42[.]xyz`; display name spoofs **paypal**.

**Indicators (defanged):**

| indicator | type | why it flagged |
|-----------|------|----------------|
| `service[at]paypa1-security[.]com` | sender | lookalike of paypal, unauthenticated |
| `hxxp://paypal-secure-login[.]com/account/verify?session=8f3a2c` | url | brand lookalike + credential lure |
| `mail-paypal-support[.]ru` | reply-to | mismatch vs From |
| `45[.]137[.]22[.]9` | origin ip | untrusted originating host |

**ATT&CK:** T1566.002 (Spearphishing Link), T1204.001 (User Execution:
Malicious Link), T1036 (Masquerading).

**Recommended action / escalation:**
- Do **not** visit the link — if detonation is wanted, do it in the sandbox, not
  from a workstation.
- Block sender domain `paypa1-security[.]com` and the lookalike host
  `paypal-secure-login[.]com`; submit both to the URL/domain blocklist.
- Purge the message from other mailboxes and check mail logs for any recipient
  who already clicked (search the origin IP / URL).
- **Escalate to Tier-2** if any recipient interacted or entered credentials —
  that becomes a potential account-compromise case, not just a blocked email.
