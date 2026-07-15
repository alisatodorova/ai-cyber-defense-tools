"""Download the latest Hayabusa release for this platform and extract it to ./hayabusa/.

Usage:
    python scripts/download_hayabusa.py
"""

import io
import json
import platform
import sys
import urllib.request
import zipfile
from pathlib import Path

REPO = "Yamato-Security/hayabusa"
API_URL = f"https://api.github.com/repos/{REPO}/releases/latest"
DEST_DIR = Path(__file__).resolve().parent.parent / "hayabusa"


def pick_asset(assets: list[dict]) -> dict:
    system = platform.system().lower()
    machine = platform.machine().lower()

    if system == "windows":
        os_tag = "win"
    elif system == "linux":
        os_tag = "lin"
    elif system == "darwin":
        os_tag = "mac"
    else:
        raise RuntimeError(f"Unsupported platform: {system}")

    if machine in ("amd64", "x86_64"):
        arch_tag = "x64"
    elif machine in ("arm64", "aarch64"):
        arch_tag = "aarch64"
    elif machine in ("x86", "i386", "i686") and os_tag == "win":
        arch_tag = "x86"
    else:
        raise RuntimeError(f"Unsupported architecture: {machine}")

    candidates = [
        a
        for a in assets
        if a["name"].endswith(".zip")
        and f"-{os_tag}-{arch_tag}" in a["name"]
        and "live-response" not in a["name"]
    ]
    if not candidates:
        raise RuntimeError(
            f"No release asset found for {os_tag}-{arch_tag}. "
            f"Available assets: {[a['name'] for a in assets]}"
        )
    # Prefer the gnu build over musl on Linux when both match.
    candidates.sort(key=lambda a: "musl" in a["name"])
    return candidates[0]


def main() -> None:
    print(f"Fetching latest release metadata from {API_URL} ...")
    req = urllib.request.Request(API_URL, headers={"User-Agent": "mcp-hayabusa-installer"})
    with urllib.request.urlopen(req) as resp:
        release = json.load(resp)

    tag = release.get("tag_name", "unknown")
    asset = pick_asset(release["assets"])
    name = asset["name"]
    size = asset["size"]
    url = asset["browser_download_url"]

    print(f"Latest release: {tag}")
    print(f"Selected asset: {name} ({size:,} bytes)")
    print(f"Downloading from {url} ...")

    req = urllib.request.Request(url, headers={"User-Agent": "mcp-hayabusa-installer"})
    with urllib.request.urlopen(req) as resp:
        data = resp.read()

    if len(data) != size:
        print(
            f"Warning: downloaded {len(data):,} bytes, expected {size:,} bytes",
            file=sys.stderr,
        )

    DEST_DIR.mkdir(parents=True, exist_ok=True)
    print(f"Extracting to {DEST_DIR} ...")
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        zf.extractall(DEST_DIR)

    # Make any extracted binaries executable on POSIX platforms.
    if platform.system().lower() != "windows":
        import stat

        for path in DEST_DIR.rglob("*"):
            if path.is_file() and path.name.lower().startswith("hayabusa"):
                path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    print("Done.")


if __name__ == "__main__":
    main()
