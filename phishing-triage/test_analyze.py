"""Tests for the phishing-triage analysis engine.

Runs entirely offline against the three bundled sample emails. No pytest
dependency — this is a plain assert-and-report script so it works in a bare
Python environment (same spirit as the rest of this repo's tooling):

    python test_analyze.py        # prints PASS/FAIL per case, exits non-zero on failure
"""

from __future__ import annotations

import sys
from pathlib import Path

from analyze import analyze_email

SAMPLES = Path(__file__).resolve().parent / "samples"


def _find_url(analysis, host_contains):
    for u in analysis["urls"]:
        if u["host"] and host_contains in u["host"]:
            return u
    return None


def check_benign():
    a = analyze_email(str(SAMPLES / "benign-newsletter.eml"))
    assert a["risk"]["verdict"] == "benign", a["risk"]
    assert a["auth_results"] == {"spf": "pass", "dkim": "pass", "dmarc": "pass"}
    assert not a["attachments"]
    assert a["attack"] == [], a["attack"]
    # Every URL must be defanged (no clickable scheme left).
    for u in a["urls"]:
        assert "http://" not in u["defanged"] and "https://" not in u["defanged"]
    return a


def check_credential_phish():
    a = analyze_email(str(SAMPLES / "credential-phish.eml"))
    assert a["risk"]["verdict"] == "likely-phish", a["risk"]
    assert a["auth_results"]["spf"] == "fail"
    assert a["auth_results"]["dkim"] == "fail"
    assert a["auth_results"]["dmarc"] == "fail"
    align = a["sender_alignment"]
    assert align["display_name_spoof"] is True
    assert align["spoofed_brand"] == "paypal"
    assert align["reply_to_mismatch"] is True
    assert align["return_path_mismatch"] is True
    lure = _find_url(a, "paypal-secure-login.com")
    assert lure is not None, "lookalike URL not extracted"
    assert lure["flags"]["lookalike_brand"] == "paypal"
    assert lure["flags"]["credential_lure"] is True
    assert lure["defanged"] == "hxxp://paypal-secure-login[.]com/account/verify?session=8f3a2c"
    ids = {t["id"] for t in a["attack"]}
    assert {"T1566.002", "T1204.001", "T1036"} <= ids, ids
    return a


def check_malware_attachment():
    a = analyze_email(str(SAMPLES / "malware-attachment.eml"))
    assert a["risk"]["verdict"] == "likely-phish", a["risk"]
    assert a["attachment_count"] == 1
    att = a["attachments"][0]
    assert att["filename"] == "Invoice_2026.pdf.html"
    assert att["risky_extension"] is True
    assert att["double_extension"] is True
    assert att["sha256"] and len(att["sha256"]) == 64
    assert a["sender_alignment"]["from_tld_suspicious"] is True  # .top
    ids = {t["id"] for t in a["attack"]}
    assert {"T1566.001", "T1204.002"} <= ids, ids
    return a


def check_bulgarian_phish():
    """Non-English coverage: structural signals are language-agnostic, and the
    Cyrillic keyword/brand additions in indicators.json fire correctly."""
    a = analyze_email(str(SAMPLES / "credential-phish-bg.eml"))
    assert a["risk"]["verdict"] == "likely-phish", a["risk"]
    # MIME-encoded Cyrillic subject decodes.
    assert a["subject"] and "ДСК" in a["subject"], a["subject"]
    # Bulgarian urgency wording scored (would be missed with English-only lists).
    assert any(ch in "".join(a["urgency_hits"]) for ch in "абвгдежзий"), a["urgency_hits"]
    lure = _find_url(a, "dskbank-online.top")
    assert lure is not None and lure["flags"]["lookalike_brand"] == "dskbank"
    return a


def check_legit_bg_bank_not_lookalike():
    """Regression: the real dskbank.bg must NOT be flagged as a lookalike of
    itself (SLD-based matching, not '.com'-assuming)."""
    from analyze import _classify_url, load_indicators
    ind = load_indicators()
    for host_url in ("https://www.dskbank.bg/login", "https://dskbank.bg/"):
        u = _classify_url(host_url, ind)
        assert u["flags"]["lookalike_brand"] is None, (host_url, u["flags"])
    # But a lookalike on another SLD still trips.
    bad = _classify_url("http://dskbank-online.top/vhod", ind)
    assert bad["flags"]["lookalike_brand"] == "dskbank"


def check_real_google_phish():
    """Real-world sample (sanitized): Google Cloud lookalike. Passes SPF+DKIM,
    so it must be caught on brand/behaviour signals, not authentication."""
    a = analyze_email(str(SAMPLES / "real-world" / "google-cloud-storage-phish.eml"))
    assert a["risk"]["verdict"] == "likely-phish", a["risk"]
    assert a["auth_results"]["spf"] == "pass" and a["auth_results"]["dkim"] == "pass"
    align = a["sender_alignment"]
    assert align["display_name_spoof"] and align["spoofed_brand"] == "google"
    assert a["tracking_pixels"], "1x1 tracking pixel not detected"
    ids = {t["id"] for t in a["attack"]}
    assert {"T1036", "T1566.002"} <= ids, ids


def check_real_econt_phish():
    """Real-world sample (sanitized): Econt courier lookalike on free hosting.
    The legit econt.com logo images must NOT be flagged; the web.app must."""
    a = analyze_email(str(SAMPLES / "real-world" / "econt-parcel-phish.eml"))
    assert a["risk"]["verdict"] == "likely-phish", a["risk"]
    align = a["sender_alignment"]
    assert align["local_part_spoof"] and align["spoofed_brand"] == "econt"
    fake = _find_url(a, "web.app")
    assert fake and fake["flags"]["lookalike_brand"] == "econt" and fake["flags"]["free_hosting"]
    legit = _find_url(a, "www.econt.com")
    assert legit and legit["flags"]["lookalike_brand"] is None, "real econt.com mis-flagged"


def check_real_samples_pii_scrubbed():
    """The committed real-world samples must not contain the recipient's PII."""
    import re as _re
    for p in (SAMPLES / "real-world").glob("*.eml"):
        txt = p.read_text(encoding="latin-1")
        assert not _re.search("alissa2000", txt, _re.IGNORECASE), f"PII leak in {p.name}"


def check_no_network_imports():
    """Guard the core promise: analyze.py performs no network access."""
    src = (Path(__file__).resolve().parent / "analyze.py").read_text(encoding="utf-8")
    for banned in ("import socket", "import urllib", "import requests", "import http.client"):
        assert banned not in src, f"analyze.py must not {banned!r} (offline-only guarantee)"


CASES = [
    ("benign-newsletter", check_benign),
    ("credential-phish", check_credential_phish),
    ("malware-attachment", check_malware_attachment),
    ("bulgarian-phish", check_bulgarian_phish),
    ("legit-bg-bank-not-lookalike", check_legit_bg_bank_not_lookalike),
    ("real-google-phish", check_real_google_phish),
    ("real-econt-phish", check_real_econt_phish),
    ("real-samples-pii-scrubbed", check_real_samples_pii_scrubbed),
    ("no-network-imports", check_no_network_imports),
]


def main() -> int:
    failures = 0
    for name, fn in CASES:
        try:
            result = fn()
            verdict = ""
            if isinstance(result, dict):
                verdict = f" -> {result['risk']['verdict']} (score {result['risk']['score']})"
            print(f"PASS  {name}{verdict}")
        except AssertionError as e:
            failures += 1
            print(f"FAIL  {name}: {e}")
        except Exception as e:  # noqa: BLE001 - surface any unexpected error as a failure
            failures += 1
            print(f"ERROR {name}: {type(e).__name__}: {e}")

    print()
    print(f"{len(CASES) - failures}/{len(CASES)} checks passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
