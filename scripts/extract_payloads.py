"""Extract payloads/commands from downloaded HackerOne reports.

Scans ``learningfromreport/*.json`` (full-disclosure HackerOne reports),
pulls out payload-like lines from each report's vulnerability_information,
groups them by weakness type, and writes:

    payloads/payload_corpus.json   machine-readable payload corpus
    payloads/README.md             human summary with top examples per type

Payloads are the exact strings researchers used (or close variants) — they
feed scanner test corpora and payload generation. Deduplicated, truncated to
a sane length, and only lines that LOOK like payloads are kept.

Usage:
    python scripts/extract_payloads.py --reports learningfromreport --out payloads
"""

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path

# Lines that look like an attack payload (heuristic, report-driven)
_PAYLOAD_RE = re.compile(
    r"curl\s|wget\s|nc\s|bash -c|/bin/sh|\bxq\{|\$\{|`[^`]{3,}`|"
    r"<?php|python\s+-c|<script[ >]|onerror=|javascript:|"
    r"['\"](?:SELECT|INSERT|UPDATE|DELETE|UNION)[^'\"]{5,}['\"]|"
    r"\b(?:../../|\.\./)[^\"'\s]{2,}|%2e%2e%2f|"
    r"\\\\r\\\\n|%0d%0a|%0D%0A|\bdata:\s*text/|\bbase64|"
    r"git clone|git://|file://|gopher://|dict://|"
    r"\{\{.*\}\}|\{%|__proto__|constructor\.prototype|"
    r"jwt\.|alg[^,]*none|verify_signature|"
    r"\bGET\s+/|\bPOST\s+/\b|Host:\s|Cookie:|Authorization:|"
    r"pickle\.loads|Marshal\.load|unserialize\(|phar://",
    re.I,
)

# Lines that are clearly noise / narrative, not payloads
_NOISE = re.compile(
    r"^\s*(?:the|and|for|with|this|that|when|using|after|before|via|from|to|a|an)\b|"
    r"^\s*[a-z]+\s+(?:is|are|was|were|has|have|can|could|should)\b|"
    r"^\s*[^:]{0,10}:?\s*$|^\s*[-*]\s*$|^\s*$|"
    r"^\s*(?:http|https)://hackerone|https?://(?:www\.)?(?:youtube|google|twitter)",
    re.I,
)

_PLACEHOLDER = re.compile(r"example\.com|yourdomain|xxxxx|<[^>]{2,40}>|\[redacted\]|REMOVED")


def _attr(data: dict) -> dict:
    inner = data.get("data", data)
    if isinstance(inner, dict):
        return inner.get("attributes", inner)
    return inner


def extract_payloads(reports_dir: Path) -> dict:
    corpus: dict = defaultdict(list)
    total_lines = 0
    for path in sorted(reports_dir.glob("*.json")):
        if path.name in ("bugcrowd_verified.json", "verified.json", "candidates.json"):
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        meta = _attr(data)
        weakness = (
            (meta.get("weakness") or {}).get("name") or meta.get("weakness_identifier") or "unknown"
        )
        info = meta.get("vulnerability_information", "") or ""
        for line in info.splitlines():
            line = line.strip()
            if not line or len(line) > 300:
                continue
            if _NOISE.search(line) or _PLACEHOLDER.search(line):
                continue
            if not _PAYLOAD_RE.search(line):
                continue
            total_lines += 1
            if line not in corpus[weakness]:
                corpus[weakness].append(line)
    return {"corpus": {k: v[:200] for k, v in corpus.items()}, "total_lines": total_lines}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Extract payloads from HackerOne reports")
    ap.add_argument("--reports", default="learningfromreport")
    ap.add_argument("--out", default="payloads")
    args = ap.parse_args(argv)

    reports_dir = Path(args.reports)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    result = extract_payloads(reports_dir)
    (out_dir / "payload_corpus.json").write_text(json.dumps(result, indent=2), encoding="utf-8")

    lines = [
        "# Payload Corpus (extracted from real HackerOne reports)",
        "",
        f"Extracted {result['total_lines']} payload-like lines from "
        f"{sum(len(v) for v in result['corpus'].values())} unique payloads "
        f"across {len(result['corpus'])} weakness types.",
        "",
    ]
    for weakness, payloads in sorted(result["corpus"].items(), key=lambda kv: -len(kv[1])):
        lines.append(f"## {weakness} ({len(payloads)})")
        lines.append("")
        for p in payloads[:6]:
            lines.append(f"- `{p}`")
        if len(payloads) > 6:
            lines.append(f"- _… +{len(payloads) - 6} more in payload_corpus.json_")
        lines.append("")
    (out_dir / "README.md").write_text("\n".join(lines), encoding="utf-8")

    print(
        f"[*] {result['total_lines']} payload lines, "
        f"{len(result['corpus'])} weakness types -> {out_dir}"
    )
    for weakness, payloads in sorted(result["corpus"].items(), key=lambda kv: -len(kv[1]))[:8]:
        print(f"    {weakness}: {len(payloads)} payloads")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
