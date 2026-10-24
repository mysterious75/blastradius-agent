"""Download the free/official reference library used for launch-readiness review.

Only public standards and freely published guidance are fetched. Nothing here
redistributes paywalled or pirated books; the manifest records the license /
terms for each item and the raw files stay local (`docs/library/raw/` is
gitignored). Re-runnable: existing files are skipped unless --force.
"""

from __future__ import annotations

import argparse
import ssl
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "docs" / "library" / "raw"

SOURCES = [
    ("owasp-top10-2025.html", "https://owasp.org/Top10/2025/"),
    ("owasp-api-top10-2023.html", "https://owasp.org/API-Security/editions/2023/en/0x11-t10/"),
    ("owasp-llm-top10.html", "https://genai.owasp.org/llm-top-10/"),
    ("owasp-asvs.zip", "https://github.com/OWASP/ASVS/archive/refs/heads/master.zip"),
    ("owasp-wstg.zip", "https://github.com/OWASP/wstg/archive/refs/heads/master.zip"),
    ("owasp-samm.html", "https://owasp.org/www-project-samm/"),
    (
        "nist-sp800-115.pdf",
        "https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-115.pdf",
    ),
    (
        "nist-sp800-218.pdf",
        "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218.pdf",
    ),
    (
        "nist-sp800-218a.pdf",
        "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218A.pdf",
    ),
    (
        "cisa-sscs-developers.pdf",
        "https://www.cisa.gov/sites/default/files/publications/ESF_SECURING_THE_SOFTWARE_SUPPLY_CHAIN_DEVELOPERS.PDF",
    ),
    ("cwe-top25-2024.html", "https://cwe.mitre.org/top25/archive/2024/2024_cwe_top25.html"),
    ("sarif-2.1.0.html", "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html"),
    ("slsa-1.0.html", "https://slsa.dev/spec/v1.0/"),
    ("scorecard-checks.md", "https://raw.githubusercontent.com/ossf/scorecard/main/docs/checks.md"),
    ("openssf-badge-criteria.html", "https://www.bestpractices.dev/en/criteria"),
    ("cyclonedx-1.6.html", "https://cyclonedx.org/docs/1.6/"),
    ("12factor.html", "https://12factor.net/"),
    ("tob-secure-contracts.html", "https://secure-contracts.com/"),
    (
        "solidity-security.html",
        "https://docs.soliditylang.org/en/latest/security-considerations.html",
    ),
    (
        "consensys-best-practices.html",
        "https://consensysdiligence.github.io/smart-contract-best-practices/",
    ),
    ("foundry-book.html", "https://book.getfoundry.sh/"),
    ("google-sre-security.html", "https://sre.google/books/building-secure-reliable-systems/"),
]

UA = "Mozilla/5.0 (compatible; blastradius-library/1.0; +https://github.com/mysterious75/blastradius-agent)"


def fetch(name: str, url: str, force: bool) -> str:
    dest = RAW / name
    if dest.exists() and not force:
        return f"skip  {name} ({dest.stat().st_size} bytes)"
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    try:
        with urllib.request.urlopen(req, timeout=90) as resp:
            data = resp.read()
            ctype = resp.headers.get("Content-Type", "")
    except (urllib.error.URLError, TimeoutError, ssl.SSLError) as exc:
        return f"FAIL  {name}: {exc}"
    dest.write_bytes(data)
    return f"ok    {name} {len(data)} bytes {ctype}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()
    RAW.mkdir(parents=True, exist_ok=True)
    failures = 0
    for name, url in SOURCES:
        result = fetch(name, url, args.force)
        print(result)
        if result.startswith("FAIL"):
            failures += 1
        time.sleep(0.4)
    print(f"\n{len(SOURCES) - failures}/{len(SOURCES)} available in {RAW}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
