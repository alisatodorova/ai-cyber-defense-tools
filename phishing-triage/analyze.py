"""Static, offline phishing-triage analysis of a single .eml file.

This module parses a raw email and scores it for phishing indicators. It is the
core logic behind the MCP server (``server.py``); keeping it here — plain
functions, standard library only — means it can be unit-tested and run from the
CLI without the ``mcp`` package or an event loop.

Two rules are non-negotiable and are the reason this tool is safe to point at a
real mailbox:

1. **No network. Ever.** Nothing here resolves DNS, connects, fetches a URL, or
   detonates an attachment. Analysis is 100% static. There is no ``urllib`` /
   ``socket`` / ``requests`` import on purpose.
2. **The email body is untrusted data.** A phishing email may contain text
   crafted to manipulate whoever (or whatever) reads it — including an LLM. This
   module only ever emits the body as *structured data* (extracted URLs,
   defanged strings, keyword hits); it never treats email content as an
   instruction, and neither should any client rendering its output.

Usage:
    python analyze.py <path-to.eml>          # prints the JSON analysis
"""

from __future__ import annotations

import email
import hashlib
import json
import re
import sys
from email import policy
from email.utils import parseaddr
from pathlib import Path

INDICATORS_FILE = Path(__file__).resolve().parent / "indicators.json"

# Score thresholds -> verdict. Tuned against the three bundled samples; treat as
# a triage prior, not a ground-truth classifier.
VERDICT_SUSPICIOUS_AT = 3
VERDICT_LIKELY_PHISH_AT = 7

# Populated on first use; the indicators file doesn't change at runtime.
_indicators_cache: dict | None = None


class EmailAnalysisError(RuntimeError):
    """Raised when an .eml file can't be read or parsed."""


def load_indicators() -> dict:
    """Load (and cache) the phishing indicator knowledge base."""
    global _indicators_cache
    if _indicators_cache is not None:
        return _indicators_cache
    try:
        with INDICATORS_FILE.open("r", encoding="utf-8") as f:
            _indicators_cache = json.load(f)
    except FileNotFoundError as e:
        raise EmailAnalysisError(
            f"Indicator knowledge base not found at {INDICATORS_FILE}"
        ) from e
    except json.JSONDecodeError as e:
        raise EmailAnalysisError(f"Indicator file is not valid JSON: {e}") from e
    return _indicators_cache


# --------------------------------------------------------------------------- #
# Defanging — render an indicator unclickable so it can be shown/logged safely.
# --------------------------------------------------------------------------- #

_SCHEME_DEFANG = [
    ("https://", "hxxps://"),
    ("http://", "hxxp://"),
    ("ftp://", "fxp://"),
]


def defang(value: str) -> str:
    """Make a URL / domain / IP / email address safe to display or paste.

    Neutralises the scheme (``http`` -> ``hxxp``), every ``.`` (-> ``[.]``) and
    ``@`` (-> ``[at]``) so the result can't be clicked or auto-linked. Idempotent
    enough for triage output; not a reversible transform.
    """
    if not value:
        return value
    out = value
    for fanged, defanged in _SCHEME_DEFANG:
        out = out.replace(fanged, defanged)
    out = out.replace(".", "[.]")
    out = out.replace("@", "[at]")
    return out


def _domain_of(addr: str) -> str:
    """Return the lowercase domain of an email address, or '' if none."""
    if not addr or "@" not in addr:
        return ""
    return addr.rsplit("@", 1)[1].strip().strip(">").lower()


def _host_of(url: str) -> str:
    """Extract the lowercase host from a URL without importing urllib.

    Kept dependency-free and deliberately forgiving: strips scheme, userinfo,
    port, path, query and fragment. Never raises.
    """
    host = url
    host = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", "", host)  # scheme
    host = host.split("/", 1)[0]  # path
    host = host.split("?", 1)[0].split("#", 1)[0]
    host = host.rsplit("@", 1)[-1]  # userinfo
    host = host.split(":", 1)[0]  # port
    return host.strip().lower()


_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_URL_RE = re.compile(r"""https?://[^\s"'<>)\]}]+""", re.IGNORECASE)
_HREF_RE = re.compile(r"""(?:href|src)\s*=\s*["']([^"']+)["']""", re.IGNORECASE)

# Used by defang_iocs() to pull indicators out of an arbitrary text blob.
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_IPV4_TOKEN_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)


def defang_iocs(text: str) -> dict:
    """Defang every URL / email / IPv4 / bare domain found in a text blob.

    Returns the list of indicators found and a ``defanged_text`` copy safe to log
    or paste. Processing order (URL -> email -> IP -> domain) matters: once a
    token is defanged its dots become ``[.]``, so later patterns won't re-match
    inside an already-neutralised indicator.
    """
    found: list[dict] = []
    seen: set[str] = set()
    working = text or ""

    def process(rx: re.Pattern, kind: str, strip=False):
        nonlocal working
        for m in rx.finditer(working):
            token = m.group(0)
            if strip:
                token = token.rstrip(".,);'\"")
            if token and token not in seen:
                seen.add(token)
                found.append({"type": kind, "value": token, "defanged": defang(token)})
        working = rx.sub(
            lambda mm: defang(mm.group(0).rstrip(".,);'\"") if strip else mm.group(0)),
            working,
        )

    process(_URL_RE, "url", strip=True)
    process(_EMAIL_RE, "email")
    process(_IPV4_TOKEN_RE, "ipv4")
    process(_DOMAIN_RE, "domain")

    return {
        "input_length": len(text or ""),
        "ioc_count": len(found),
        "iocs": found,
        "defanged_text": working,
    }


# --------------------------------------------------------------------------- #
# Parsing helpers
# --------------------------------------------------------------------------- #

def _load_message(eml_path: str):
    path = Path(eml_path)
    if not path.is_file():
        raise EmailAnalysisError(f"Email file not found: {eml_path}")
    try:
        raw = path.read_bytes()
    except OSError as e:
        raise EmailAnalysisError(f"Failed to read {eml_path}: {e}") from e
    try:
        msg = email.message_from_bytes(raw, policy=policy.default)
    except Exception as e:  # email lib raises a grab-bag of types on junk input
        raise EmailAnalysisError(f"Failed to parse email: {e}") from e
    return msg, raw


def _bodies(msg) -> tuple[str, str]:
    """Return (plain_text, html) body content, defensively decoded."""
    plain, html = [], []
    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue
        disp = (part.get_content_disposition() or "").lower()
        if disp == "attachment":
            continue
        ctype = part.get_content_type()
        if ctype not in ("text/plain", "text/html"):
            continue
        try:
            content = part.get_content()
        except (LookupError, ValueError, UnicodeDecodeError):
            payload = part.get_payload(decode=True) or b""
            content = payload.decode("utf-8", errors="replace")
        if ctype == "text/plain":
            plain.append(content)
        else:
            html.append(content)
    return "\n".join(plain), "\n".join(html)


def _extract_urls(plain: str, html: str) -> list[str]:
    """Collect unique URLs from body text and HTML href/src attributes."""
    found: list[str] = []
    seen: set[str] = set()
    for match in _URL_RE.findall(plain + "\n" + html):
        url = match.rstrip(".,);'\"")
        if url not in seen:
            seen.add(url)
            found.append(url)
    for href in _HREF_RE.findall(html):
        href = href.strip()
        if href.lower().startswith("http") and href not in seen:
            seen.add(href)
            found.append(href.rstrip(".,);'\""))
    return found


def _headers(msg) -> dict:
    keys = ["From", "Reply-To", "Return-Path", "To", "Subject", "Date", "Message-ID"]
    return {k: (msg.get(k) or "").strip() or None for k in keys}


def _sender_alignment(msg) -> dict:
    from_name, from_addr = parseaddr(msg.get("From", ""))
    _, reply_addr = parseaddr(msg.get("Reply-To", ""))
    _, return_addr = parseaddr(msg.get("Return-Path", ""))

    from_domain = _domain_of(from_addr)
    reply_domain = _domain_of(reply_addr)
    return_domain = _domain_of(return_addr)

    reply_to_mismatch = bool(reply_domain) and reply_domain != from_domain
    return_path_mismatch = bool(return_domain) and return_domain != from_domain

    from_tld = from_domain.rsplit(".", 1)[-1] if "." in from_domain else ""

    # Display-name spoof: the human-readable name name-drops a brand that the
    # actual sending domain does not belong to (classic "PayPal Service"
    # <x@random.tld>).
    indicators = load_indicators()
    name_lower = (from_name or "").lower()
    local_part = from_addr.split("@", 1)[0].lower() if from_addr and "@" in from_addr else ""
    display_name_spoof = False
    local_part_spoof = False
    spoofed_brand = None
    for brand in indicators.get("lookalike_brands", []):
        if brand in name_lower and brand not in from_domain:
            display_name_spoof = True
            spoofed_brand = brand
            break
    if not display_name_spoof:
        # The sender's local part can also claim a brand its domain doesn't back
        # (econt-express-bg@asiakas.life). Same signal, different field.
        for brand in indicators.get("lookalike_brands", []):
            if brand in local_part and brand not in from_domain:
                local_part_spoof = True
                spoofed_brand = brand
                break

    from_tld_suspicious = bool(from_tld) and from_tld in {
        t.lower() for t in indicators.get("suspicious_tlds", [])
    }

    return {
        "from_name": from_name or None,
        "from_address": from_addr or None,
        "from_domain": from_domain or None,
        "from_tld": from_tld or None,
        "from_tld_suspicious": from_tld_suspicious,
        "reply_to_domain": reply_domain or None,
        "return_path_domain": return_domain or None,
        "reply_to_mismatch": reply_to_mismatch,
        "return_path_mismatch": return_path_mismatch,
        "display_name_spoof": display_name_spoof,
        "local_part_spoof": local_part_spoof,
        "spoofed_brand": spoofed_brand,
    }


_AUTH_RESULT_RE = {
    "spf": re.compile(r"\bspf=(\w+)", re.IGNORECASE),
    "dkim": re.compile(r"\bdkim=(\w+)", re.IGNORECASE),
    "dmarc": re.compile(r"\bdmarc=(\w+)", re.IGNORECASE),
}


def _auth_results(msg) -> dict:
    """Parse SPF/DKIM/DMARC verdicts out of Authentication-Results headers."""
    blob = " ".join(msg.get_all("Authentication-Results", []))
    received_spf = " ".join(msg.get_all("Received-SPF", []))
    haystack = f"{blob} {received_spf}"

    results = {}
    for mech, rx in _AUTH_RESULT_RE.items():
        m = rx.search(haystack)
        results[mech] = m.group(1).lower() if m else "none"
    # Received-SPF sometimes only states the result word (pass/fail) up front.
    if results["spf"] == "none" and received_spf:
        lead = received_spf.strip().split(" ", 1)[0].lower()
        if lead in ("pass", "fail", "softfail", "neutral", "none"):
            results["spf"] = lead
    return results


def _received_chain(msg) -> list[dict]:
    """Ordered hop list (origin first) from the Received headers."""
    hops = msg.get_all("Received", [])
    chain = []
    # Received headers are prepended, so the last one is the origin -> reverse.
    for i, raw in enumerate(reversed(hops)):
        collapsed = re.sub(r"\s+", " ", raw).strip()
        ip = None
        ip_match = re.search(r"[\[(](\d{1,3}(?:\.\d{1,3}){3})[\])]", collapsed)
        if ip_match:
            ip = ip_match.group(1)
        ts = collapsed.rsplit(";", 1)[1].strip() if ";" in collapsed else None
        chain.append({"hop": i + 1, "ip": ip, "timestamp": ts, "raw": collapsed})
    return chain


def _attachments(msg) -> list[dict]:
    indicators = load_indicators()
    risky_exts = {e.lower() for e in indicators.get("risky_extensions", [])}
    out = []
    for part in msg.walk():
        disp = (part.get_content_disposition() or "").lower()
        filename = part.get_filename()
        if disp != "attachment" and not filename:
            continue
        if part.get_content_maintype() == "multipart":
            continue
        payload = part.get_payload(decode=True) or b""
        name = filename or "(unnamed)"
        # Double-extension trick: invoice.pdf.html, scan.jpg.exe, ...
        suffixes = [s.lower() for s in Path(name).suffixes]
        final_ext = suffixes[-1] if suffixes else ""
        double_ext = len(suffixes) >= 2 and suffixes[-1] in risky_exts
        out.append(
            {
                "filename": name,
                "content_type": part.get_content_type(),
                "size_bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest() if payload else None,
                "extension": final_ext or None,
                "risky_extension": final_ext in risky_exts,
                "double_extension": double_ext,
            }
        )
    return out


def _classify_url(url: str, indicators: dict) -> dict:
    host = _host_of(url)
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    lowered = url.lower()

    is_shortener = any(host == s or host.endswith("." + s)
                       for s in indicators.get("url_shorteners", []))
    raw_ip = bool(_IPV4_RE.match(host))
    punycode = "xn--" in host
    suspicious_tld = tld in {t.lower() for t in indicators.get("suspicious_tlds", [])}
    credential_lure = any(k in lowered for k in indicators.get("credential_lure_keywords", []))
    free_hosting = any(host == h or host.endswith("." + h)
                       for h in indicators.get("free_hosting_hosts", []))

    # A brand is impersonated when its name appears in the host but is NOT the
    # registrable label (second-level domain). This is TLD-agnostic on purpose:
    # the real domain may be paypal.com or dskbank.bg — both have the brand as
    # their SLD, so neither is a lookalike. "paypal-secure-login.com" (SLD
    # "paypal-secure-login") and "login.paypal.com.evil.top" (SLD "evil") are.
    labels = host.split(".")
    sld = labels[-2] if len(labels) >= 2 else host
    lookalike_brand = None
    for brand in indicators.get("lookalike_brands", []):
        if brand in host and sld != brand:
            lookalike_brand = brand
            break

    return {
        "url": url,
        "defanged": defang(url),
        "host": host or None,
        "flags": {
            "shortener": is_shortener,
            "raw_ip": raw_ip,
            "punycode": punycode,
            "suspicious_tld": suspicious_tld,
            "credential_lure": credential_lure,
            "free_hosting": free_hosting,
            "lookalike_brand": lookalike_brand,
        },
    }


def _keyword_hits(text: str, keywords: list[str]) -> list[str]:
    lowered = text.lower()
    return sorted({k for k in keywords if k in lowered})


def _sld(host: str) -> str:
    """Registrable-ish second-level label (paypal.com -> paypal, a.b.co -> b)."""
    labels = (host or "").split(".")
    return labels[-2] if len(labels) >= 2 else (host or "")


_IMG_TAG_RE = re.compile(r"<img\b[^>]*>", re.IGNORECASE)
_DIM_RE = re.compile(r"""\b(width|height)\s*=\s*["']?\s*(\d+)""", re.IGNORECASE)
_IMG_SRC_RE = re.compile(r"""\bsrc\s*=\s*["']([^"']+)["']""", re.IGNORECASE)


def _tracking_pixels(html: str) -> list[str]:
    """Defanged srcs of 1x1 remote images (invisible open/beacon trackers)."""
    pixels = []
    for tag in _IMG_TAG_RE.findall(html):
        dims = {m.group(1).lower(): int(m.group(2)) for m in _DIM_RE.finditer(tag)}
        if dims.get("width", 99) <= 1 and dims.get("height", 99) <= 1:
            src = _IMG_SRC_RE.search(tag)
            if src and src.group(1).lower().startswith("http"):
                pixels.append(defang(src.group(1)))
    return pixels


# --------------------------------------------------------------------------- #
# Scoring + ATT&CK mapping
# --------------------------------------------------------------------------- #

def _score(alignment, auth, urls, attachments, urgency_hits, tracking_pixels) -> dict:
    reasons: list[dict] = []

    def add(reason: str, weight: int):
        reasons.append({"reason": reason, "weight": weight})

    # Authentication failures.
    for mech in ("spf", "dkim", "dmarc"):
        verdict = auth.get(mech)
        if verdict in ("fail", "softfail"):
            weight = 3 if mech == "dmarc" else 2
            add(f"{mech.upper()} {verdict}", weight)

    # Sender alignment.
    if alignment["display_name_spoof"]:
        add(f"Display name impersonates '{alignment['spoofed_brand']}' but sending "
            f"domain is {alignment['from_domain']}", 3)
    elif alignment.get("local_part_spoof"):
        add(f"Sender address ({alignment['from_address']}) claims brand "
            f"'{alignment['spoofed_brand']}' but domain is {alignment['from_domain']}", 3)
    if alignment["reply_to_mismatch"]:
        add(f"Reply-To domain ({alignment['reply_to_domain']}) differs from "
            f"From domain ({alignment['from_domain']})", 2)
    if alignment["return_path_mismatch"]:
        add(f"Return-Path domain ({alignment['return_path_domain']}) differs from "
            f"From domain ({alignment['from_domain']})", 1)
    if alignment["from_tld_suspicious"]:
        add(f"Sender domain uses a high-abuse TLD (.{alignment['from_tld']})", 2)

    # URLs (cap each category so one email with many links can't run away).
    def cap_add(condition_urls, reason_fmt, weight, cap=2):
        hit = [u for u in condition_urls]
        for u in hit[:cap]:
            add(reason_fmt.format(host=u["host"], brand=u["flags"]["lookalike_brand"]), weight)

    cap_add([u for u in urls if u["flags"]["lookalike_brand"]],
            "Link to brand-lookalike host {host} (impersonates '{brand}')", 3)
    cap_add([u for u in urls if u["flags"]["raw_ip"]],
            "Link points directly at an IP address ({host})", 2)
    cap_add([u for u in urls if u["flags"]["punycode"]],
            "Link uses punycode/IDN host ({host}) — possible homograph", 3)
    cap_add([u for u in urls if u["flags"]["suspicious_tld"]],
            "Link uses a high-abuse TLD ({host})", 2)
    cap_add([u for u in urls if u["flags"]["shortener"]],
            "Link uses a URL shortener ({host}) — destination hidden", 1)
    cap_add([u for u in urls if u["flags"]["free_hosting"]],
            "Link hosted on free app/site hosting ({host}) — brands don't host logins there", 2)
    if any(u["flags"]["credential_lure"] for u in urls):
        add("Link path/query contains credential-harvest keywords "
            "(login/verify/account/…)", 2)

    # Brand impersonation whose links go somewhere unrelated to both the
    # impersonated brand and the sender's own domain (a Google email linking to
    # bridgejeanni.com). Counted once.
    brand = alignment.get("spoofed_brand")
    if brand:
        sender_sld = _sld(alignment.get("from_domain") or "")
        offsite = [
            u for u in urls
            if u["host"] and brand not in u["host"]
            and _sld(u["host"]) not in (brand, sender_sld)
        ]
        if offsite:
            add(f"Impersonates '{brand}' but links to an unrelated domain "
                f"({offsite[0]['host']}) — neither the brand nor the sender", 2)

    if tracking_pixels:
        add(f"Contains a 1x1 remote tracking pixel ({tracking_pixels[0]})", 1)

    # Attachments.
    for a in attachments:
        if a["double_extension"]:
            add(f"Attachment '{a['filename']}' uses a double extension "
                f"(disguised {a['extension']})", 4)
        elif a["risky_extension"]:
            add(f"Attachment '{a['filename']}' has a high-risk extension "
                f"({a['extension']})", 3)

    # Social-engineering urgency language.
    if urgency_hits:
        shown = ", ".join(urgency_hits[:4])
        add(f"Urgency/pressure language in subject or body ({shown})", 1)

    score = sum(r["weight"] for r in reasons)
    if score >= VERDICT_LIKELY_PHISH_AT:
        verdict = "likely-phish"
    elif score >= VERDICT_SUSPICIOUS_AT:
        verdict = "suspicious"
    else:
        verdict = "benign"

    return {"score": score, "verdict": verdict, "reasons": reasons}


_ATTACK_NAMES = {
    "T1566.001": "Phishing: Spearphishing Attachment",
    "T1566.002": "Phishing: Spearphishing Link",
    "T1204.001": "User Execution: Malicious Link",
    "T1204.002": "User Execution: Malicious File",
    "T1036": "Masquerading",
}


def _attack_mapping(alignment, urls, attachments) -> list[dict]:
    ids: set[str] = set()
    if any(a["risky_extension"] or a["double_extension"] for a in attachments):
        ids.update({"T1566.001", "T1204.002"})
    suspicious_url = any(
        any(f for f in u["flags"].values()) for u in urls
    )
    brand_impersonation = (
        alignment["display_name_spoof"] or alignment.get("local_part_spoof")
        or any(u["flags"]["lookalike_brand"] for u in urls)
    )
    has_link = any(u["host"] for u in urls)
    # A malicious link (spearphishing link) is indicated either by a URL that
    # flagged on its own, or by a brand-impersonating email that lures a click.
    if suspicious_url or (brand_impersonation and has_link):
        ids.update({"T1566.002", "T1204.001"})
    if brand_impersonation:
        ids.add("T1036")
    return [{"id": tid, "name": _ATTACK_NAMES[tid]} for tid in sorted(ids)]


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #

def analyze_email(eml_path: str) -> dict:
    """Analyze an .eml file and return a structured triage report (dict).

    Purely static: no network access, no attachment execution. Every URL and
    address in the returned dict is also provided in a defanged form.
    """
    indicators = load_indicators()
    msg, raw = _load_message(eml_path)

    headers = _headers(msg)
    alignment = _sender_alignment(msg)
    auth = _auth_results(msg)
    received = _received_chain(msg)
    attachments = _attachments(msg)

    plain, html = _bodies(msg)
    urls = [_classify_url(u, indicators) for u in _extract_urls(plain, html)]
    tracking_pixels = _tracking_pixels(html)

    subject = headers.get("Subject") or ""
    urgency_hits = _keyword_hits(subject + "\n" + plain + "\n" + html,
                                 indicators.get("urgency_keywords", []))

    risk = _score(alignment, auth, urls, attachments, urgency_hits, tracking_pixels)
    attack = _attack_mapping(alignment, urls, attachments)

    return {
        "file": str(Path(eml_path).resolve()),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "subject": subject or None,
        "headers": headers,
        "sender_alignment": alignment,
        "auth_results": auth,
        "received_chain": received,
        "urls": urls,
        "url_count": len(urls),
        "tracking_pixels": tracking_pixels,
        "attachments": attachments,
        "attachment_count": len(attachments),
        "urgency_hits": urgency_hits,
        "attack": attack,
        "risk": risk,
    }


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(json.dumps({"error": "Usage: analyze.py <path-to.eml>"}), file=sys.stderr)
        return 2
    try:
        result = analyze_email(argv[1])
    except EmailAnalysisError as e:
        print(json.dumps({"error": str(e)}), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
