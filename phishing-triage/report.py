"""Render a phishing-triage analysis (from analyze.py) as a standalone HTML report.

The output is a single self-contained .html file: inline CSS + a few lines of
inline JS (copy-to-clipboard), no external requests, light/dark aware. It is the
"Reports & Artifacts" deliverable — the thing an analyst screenshots into a
ticket or hands to a lead.

Everything shown is already defanged by analyze.py; this module only escapes and
lays out. It never re-fangs an indicator and never emits a clickable link to a
sender-supplied URL.
"""

from __future__ import annotations

import datetime as _dt
import html
import json
from pathlib import Path

VERDICT_STYLE = {
    "benign": ("#1a7f37", "#dafbe1", "#116329", "Benign"),
    "suspicious": ("#9a6700", "#fff8c5", "#7d4e00", "Suspicious"),
    "likely-phish": ("#cf222e", "#ffebe9", "#a40e26", "Likely Phish"),
}


def _esc(value) -> str:
    return html.escape("" if value is None else str(value))


def _yesno(flag: bool, true_label="yes", false_label="no") -> str:
    cls = "bad" if flag else "ok"
    return f'<span class="pill {cls}">{true_label if flag else false_label}</span>'


def _auth_pill(verdict: str) -> str:
    v = (verdict or "none").lower()
    cls = {"pass": "ok", "fail": "bad", "softfail": "warn",
           "neutral": "warn", "none": "muted"}.get(v, "muted")
    return f'<span class="pill {cls}">{_esc(v)}</span>'


def _flag_chips(flags: dict) -> str:
    chips = []
    labels = {
        "shortener": "shortener",
        "raw_ip": "raw-IP",
        "punycode": "punycode/IDN",
        "suspicious_tld": "high-abuse TLD",
        "credential_lure": "credential lure",
        "free_hosting": "free hosting",
    }
    for key, label in labels.items():
        if flags.get(key):
            chips.append(f'<span class="chip bad">{label}</span>')
    if flags.get("lookalike_brand"):
        chips.append(f'<span class="chip bad">lookalike: {_esc(flags["lookalike_brand"])}</span>')
    return " ".join(chips) or '<span class="muted">—</span>'


def _copy_cell(defanged: str) -> str:
    safe = _esc(defanged)
    return (f'<code>{safe}</code> '
            f'<button class="copy" data-copy="{safe}" title="Copy defanged value">copy</button>')


def _reasons_rows(reasons: list[dict]) -> str:
    if not reasons:
        return '<tr><td colspan="2" class="muted">No scored indicators.</td></tr>'
    rows = []
    for r in reasons:
        rows.append(
            f'<tr><td class="wt">+{_esc(r["weight"])}</td><td>{_esc(r["reason"])}</td></tr>'
        )
    return "\n".join(rows)


def _url_rows(urls: list[dict]) -> str:
    if not urls:
        return '<tr><td colspan="3" class="muted">No URLs found in the message body.</td></tr>'
    rows = []
    for u in urls:
        rows.append(
            "<tr>"
            f"<td>{_copy_cell(u['defanged'])}</td>"
            f"<td><code>{_esc(u['host'])}</code></td>"
            f"<td>{_flag_chips(u['flags'])}</td>"
            "</tr>"
        )
    return "\n".join(rows)


def _attachment_rows(attachments: list[dict]) -> str:
    if not attachments:
        return '<tr><td colspan="5" class="muted">No attachments.</td></tr>'
    rows = []
    for a in attachments:
        risky = a["risky_extension"] or a["double_extension"]
        note = "double-extension" if a["double_extension"] else (
            "risky type" if a["risky_extension"] else "—")
        rows.append(
            "<tr>"
            f"<td><code>{_esc(a['filename'])}</code></td>"
            f"<td>{_esc(a['content_type'])}</td>"
            f"<td>{_esc(a['size_bytes'])} B</td>"
            f"<td>{_yesno(risky, note, 'no')}</td>"
            f"<td class='hash'><code>{_esc(a['sha256'])}</code></td>"
            "</tr>"
        )
    return "\n".join(rows)


def _hop_rows(chain: list[dict]) -> str:
    if not chain:
        return '<tr><td colspan="3" class="muted">No Received headers.</td></tr>'
    rows = []
    for h in chain:
        rows.append(
            "<tr>"
            f"<td>{_esc(h['hop'])}</td>"
            f"<td><code>{_esc(h['ip']) or '—'}</code></td>"
            f"<td>{_esc(h['timestamp']) or '—'}</td>"
            "</tr>"
        )
    return "\n".join(rows)


def _attack_chips(attack: list[dict]) -> str:
    if not attack:
        return '<span class="muted">No techniques mapped.</span>'
    return " ".join(
        f'<span class="chip attack">{_esc(t["id"])} · {_esc(t["name"])}</span>' for t in attack
    )


def _align_rows(a: dict) -> str:
    rows = [
        ("From", a.get("from_address"), None),
        ("From domain", a.get("from_domain"),
         "high-abuse TLD" if a.get("from_tld_suspicious") else None),
        ("Reply-To domain", a.get("reply_to_domain"),
         "mismatch" if a.get("reply_to_mismatch") else None),
        ("Return-Path domain", a.get("return_path_domain"),
         "mismatch" if a.get("return_path_mismatch") else None),
    ]
    out = []
    for label, value, flag in rows:
        flag_html = f'<span class="pill bad">{_esc(flag)}</span>' if flag else ""
        out.append(
            f"<tr><td>{_esc(label)}</td><td><code>{_esc(value) or '—'}</code> {flag_html}</td></tr>"
        )
    if a.get("display_name_spoof"):
        out.append(
            '<tr><td>Display name</td><td>'
            f'<code>{_esc(a.get("from_name"))}</code> '
            f'<span class="pill bad">impersonates {_esc(a.get("spoofed_brand"))}</span></td></tr>'
        )
    return "\n".join(out)


def render_report(analysis: dict, generated_at: str | None = None) -> str:
    verdict = analysis["risk"]["verdict"]
    fg, bg, accent, label = VERDICT_STYLE.get(verdict, VERDICT_STYLE["suspicious"])
    generated = generated_at or _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    auth = analysis["auth_results"]

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Phishing Triage - {_esc(analysis.get('subject') or 'email')}</title>
<style>
  :root {{
    --bg:#ffffff; --fg:#1f2328; --muted:#656d76; --card:#f6f8fa; --border:#d0d7de;
    --code:#eaeef2; --ok-bg:#dafbe1; --ok-fg:#116329; --bad-bg:#ffebe9; --bad-fg:#a40e26;
    --warn-bg:#fff8c5; --warn-fg:#7d4e00; --accent:{accent};
  }}
  @media (prefers-color-scheme: dark) {{
    :root {{
      --bg:#0d1117; --fg:#e6edf3; --muted:#8b949e; --card:#161b22; --border:#30363d;
      --code:#1f2630; --ok-bg:#1a3325; --ok-fg:#4ac26b; --bad-bg:#3a1a1f; --bad-fg:#ff7b72;
      --warn-bg:#3a2f14; --warn-fg:#e3b341;
    }}
  }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; padding:2rem 1.25rem; background:var(--bg); color:var(--fg);
    font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif; }}
  main {{ max-width:920px; margin:0 auto; }}
  h1 {{ font-size:1.35rem; margin:0 0 .25rem; }}
  h2 {{ font-size:1.05rem; margin:2rem 0 .6rem; padding-bottom:.3rem;
    border-bottom:1px solid var(--border); }}
  .sub {{ color:var(--muted); font-size:.85rem; word-break:break-all; }}
  .banner {{ display:flex; align-items:center; gap:1rem; flex-wrap:wrap;
    background:{bg}; color:{fg}; border:1px solid var(--border); border-left:6px solid {accent};
    border-radius:10px; padding:1rem 1.25rem; margin:1rem 0 .5rem; }}
  .banner .verdict {{ font-size:1.25rem; font-weight:700; }}
  .banner .score {{ margin-left:auto; font-size:.9rem; opacity:.85; }}
  table {{ width:100%; border-collapse:collapse; margin:.25rem 0; font-size:.9rem; }}
  th,td {{ text-align:left; padding:.5rem .6rem; border-bottom:1px solid var(--border);
    vertical-align:top; }}
  th {{ color:var(--muted); font-weight:600; font-size:.8rem; text-transform:uppercase;
    letter-spacing:.02em; }}
  td.wt {{ font-variant-numeric:tabular-nums; color:var(--bad-fg); font-weight:700; width:3rem; }}
  code {{ background:var(--code); padding:.1rem .35rem; border-radius:5px; font-size:.85em;
    word-break:break-all; }}
  td.hash code {{ font-size:.72em; }}
  .muted {{ color:var(--muted); }}
  .pill {{ display:inline-block; padding:.05rem .5rem; border-radius:999px; font-size:.75rem;
    font-weight:600; }}
  .pill.ok {{ background:var(--ok-bg); color:var(--ok-fg); }}
  .pill.bad {{ background:var(--bad-bg); color:var(--bad-fg); }}
  .pill.warn {{ background:var(--warn-bg); color:var(--warn-fg); }}
  .pill.muted {{ background:var(--code); color:var(--muted); }}
  .chip {{ display:inline-block; padding:.1rem .5rem; margin:.1rem .1rem; border-radius:6px;
    font-size:.75rem; border:1px solid var(--border); }}
  .chip.bad {{ background:var(--bad-bg); color:var(--bad-fg); border-color:transparent; }}
  .chip.attack {{ background:var(--card); color:var(--fg); }}
  .authgrid {{ display:flex; gap:.75rem; flex-wrap:wrap; margin:.5rem 0; }}
  .authgrid div {{ background:var(--card); border:1px solid var(--border); border-radius:8px;
    padding:.6rem .9rem; min-width:120px; }}
  .authgrid .k {{ color:var(--muted); font-size:.75rem; text-transform:uppercase; }}
  button.copy {{ font:inherit; font-size:.72rem; padding:.05rem .4rem; cursor:pointer;
    border:1px solid var(--border); border-radius:5px; background:var(--card); color:var(--muted); }}
  button.copy:hover {{ color:var(--fg); }}
  footer {{ margin-top:2.5rem; padding-top:1rem; border-top:1px solid var(--border);
    color:var(--muted); font-size:.8rem; }}
</style>
</head>
<body>
<main>
  <h1>Phishing Triage Report</h1>
  <div class="sub">{_esc(analysis.get('subject') or '(no subject)')}</div>

  <div class="banner">
    <span class="verdict">{_esc(label)}</span>
    <span>{_esc(len(analysis['risk']['reasons']))} scored indicator(s)</span>
    <span class="score">risk score {_esc(analysis['risk']['score'])}</span>
  </div>
  <div class="sub">File: <code>{_esc(analysis['file'])}</code><br>
    SHA-256: <code>{_esc(analysis['sha256'])}</code> · Generated {_esc(generated)}</div>

  <h2>Why this verdict</h2>
  <table><thead><tr><th>Wt</th><th>Indicator</th></tr></thead>
  <tbody>{_reasons_rows(analysis['risk']['reasons'])}</tbody></table>

  <h2>Authentication</h2>
  <div class="authgrid">
    <div><div class="k">SPF</div>{_auth_pill(auth.get('spf'))}</div>
    <div><div class="k">DKIM</div>{_auth_pill(auth.get('dkim'))}</div>
    <div><div class="k">DMARC</div>{_auth_pill(auth.get('dmarc'))}</div>
  </div>
  <table><tbody>{_align_rows(analysis['sender_alignment'])}</tbody></table>

  <h2>ATT&amp;CK techniques</h2>
  <p>{_attack_chips(analysis['attack'])}</p>

  <h2>URLs ({_esc(analysis['url_count'])})</h2>
  <table><thead><tr><th>Defanged URL</th><th>Host</th><th>Flags</th></tr></thead>
  <tbody>{_url_rows(analysis['urls'])}</tbody></table>

  <h2>Attachments ({_esc(analysis['attachment_count'])})</h2>
  <table><thead><tr><th>Filename</th><th>Type</th><th>Size</th><th>Risk</th><th>SHA-256</th></tr></thead>
  <tbody>{_attachment_rows(analysis['attachments'])}</tbody></table>

  <h2>Delivery path (Received hops, origin first)</h2>
  <table><thead><tr><th>Hop</th><th>IP</th><th>Timestamp</th></tr></thead>
  <tbody>{_hop_rows(analysis['received_chain'])}</tbody></table>

  <footer>
    Static analysis only &mdash; no URL was visited and no attachment was opened or executed.
    All indicators are <strong>defanged</strong>; refang them only inside an isolated analysis
    environment. Verdict and score are a triage prior, not a verdict of last resort &mdash;
    confirm before acting.
  </footer>
</main>
<script>
  document.querySelectorAll("button.copy").forEach(function (b) {{
    b.addEventListener("click", function () {{
      navigator.clipboard.writeText(b.getAttribute("data-copy")).then(function () {{
        var t = b.textContent; b.textContent = "copied"; setTimeout(function () {{ b.textContent = t; }}, 1200);
      }});
    }});
  }});
</script>
</body>
</html>
"""


def write_report(analysis: dict, out_path: str) -> str:
    """Render and write the report; returns the resolved output path."""
    path = Path(out_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_report(analysis), encoding="utf-8")
    return str(path.resolve())


if __name__ == "__main__":
    import sys
    from analyze import analyze_email

    if len(sys.argv) not in (2, 3):
        print(json.dumps({"error": "Usage: report.py <path-to.eml> [out.html]"}), file=sys.stderr)
        sys.exit(2)
    a = analyze_email(sys.argv[1])
    out = sys.argv[2] if len(sys.argv) == 3 else f"reports/{Path(sys.argv[1]).stem}.html"
    print(write_report(a, out))
