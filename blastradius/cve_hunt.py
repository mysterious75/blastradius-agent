"""Exploitation hunting — cross-reference findings with known-exploited CVEs.

Enrichment layer over the static findings: pulls the CISA Known Exploited
Vulnerabilities (KEV) catalog, the FIRST EPSS exploit-probability feed and
(optionally) NVD CVSS v4 severities, then tags findings whose CWE or
vulnerability class matches a KEV entry. Every source is a free key-less read
and is **offline-first**: network failures fall back to the SQLite cache and
never raise — enrichment only, never a gate.

Heuristic-only by design: a matched KEV CVE upgrades a finding to *candidate*
status. Nothing here produces the ``[VULNERABLE]`` execution marker (that
belongs to the sandbox); the KEV/EPSS signal just prioritises what to prove
first.
"""

import json
import os
import urllib.parse
import urllib.request
from typing import Dict, List, Optional

from blastradius.db.database import SQLiteDB

KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API_URL = "https://api.first.org/data/v1/epss"

USER_AGENT = "BlastRadius-CVE/1.0"
KEV_CACHE_TTL_DAYS = 1

# Set to False when the KEV feed could not be reached (flags offline runs).
network_available = True

# vuln_type -> substrings to search in a KEV entry's vulnerabilityName
# (heuristic keyword bridge between static-scan classes and the KEV catalog).
KEYWORD_MAP = {
    "xss": ["cross-site scripting", "xss"],
    "sqli": ["sql injection", "sqli"],
    "graphql": ["sql injection", "graphql injection"],
    "nosqli": ["nosql injection", "mongo"],
    "rce": [
        "remote code execution",
        "arbitrary code execution",
        "code execution",
        "command injection",
    ],
    "cmd_injection": ["command injection", "remote code execution"],
    "traversal": ["path traversal", "directory traversal", "arbitrary file"],
    "ssrf": ["server-side request forgery", "server side request forgery", "ssrf"],
    "ssti": ["template injection"],
    "xxe": ["xml external entity", "xxe"],
    "deserialization": ["deserialization", "deserialisation", "deserialize"],
    "auth_bypass": ["authentication bypass", "privilege escalation"],
    "idor": ["insecure direct object reference", "idor", "broken object"],
    "jwt": ["jwt", "token"],
    "crlf": ["header injection", "response splitting", "crlf"],
    "proto_pollution": ["prototype pollution"],
    "ci_injection": ["ci", "workflow"],
}

# vuln_type -> phrase searched in the KEV vulnerabilityName when no CWE match.
GENERIC_KEYWORDS = ("xss", "sql", "rce", "path traversal", "ssrf", "ssti", "xxe")


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


def _normalize_cwe(cwe: str) -> str:
    """Normalise a CWE id (``cwe-79`` / ``CWE 79`` / ``CWE-79`` -> ``CWE-79``)."""
    if not cwe:
        return ""
    return "".join(ch for ch in cwe.strip().upper() if ch not in "-_: ")


def parse_kev(text: str) -> List[dict]:
    """Parse the raw KEV feed JSON into a list of entry dicts.

    Handles both the CISA feed envelope (``{"vulnerabilities": [...]}``) and a
    bare list of entries (saved ``--kev-file`` snapshots). Each entry keeps
    ``cveID``, ``vendorProject``, ``product``, ``vulnerabilityName``,
    ``dateAdded``, ``cwes`` (list) and ``notes``.
    """
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return []
    if isinstance(data, dict):
        data = data.get("vulnerabilities") or []
    if not isinstance(data, list):
        return []
    entries = []
    for raw in data:
        if not isinstance(raw, dict) or not raw.get("cveID"):
            continue
        entries.append(
            {
                "cveID": raw.get("cveID"),
                "vendorProject": raw.get("vendorProject") or "",
                "product": raw.get("product") or "",
                "vulnerabilityName": raw.get("vulnerabilityName") or "",
                "dateAdded": raw.get("dateAdded") or "",
                "cwes": raw.get("cwes") or [],
                "notes": raw.get("notes") or "",
            }
        )
    return entries


def load_kev_file(path) -> List[dict]:
    """Read a saved KEV JSON snapshot from disk (feed envelope or entry list)."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return parse_kev(fh.read())


# ---------------------------------------------------------------------------
# CISA KEV feed (offline-first, SQLite cache)
# ---------------------------------------------------------------------------


def fetch_kev(timeout: int = 30) -> List[dict]:
    """Fetch and parse the CISA KEV catalog.

    On success the parsed entries are cached in SQLite (single row, 1-day TTL).
    On network failure the cache is returned if present, otherwise ``[]``.
    Never raises.
    """
    global network_available
    network_available = True

    db = None
    try:
        db = SQLiteDB()
    except Exception:
        pass

    try:
        req = urllib.request.Request(KEV_FEED_URL, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            text = resp.read().decode("utf-8", errors="replace")
        entries = parse_kev(text)
        if entries:
            if db is not None:
                try:
                    db.save_kev(entries)
                except Exception:
                    pass
            return entries
    except Exception:
        network_available = False

    # network failure (or an unusable payload): fall back to the cache
    if db is not None:
        try:
            cached = db.get_kev(ttl_days=None)
            if cached:
                return cached
        except Exception:
            pass
    return []


# ---------------------------------------------------------------------------
# NVD (best-effort: KEV flag + CVSSv4 severity, v31 fallback)
# ---------------------------------------------------------------------------


def _nvd_request(cve_id: str, timeout: int) -> Optional[dict]:
    """GET one CVE record from the NVD API 2.0. Returns parsed JSON or None."""
    params = urllib.parse.urlencode({"cveId": cve_id})
    headers = {"User-Agent": USER_AGENT}
    key = os.getenv("NVD_API_KEY")
    if key:
        headers["apiKey"] = key
    req = urllib.request.Request(f"{NVD_CVE_URL}?{params}", headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", errors="replace"))


def nvd_has_kev(cve_id: str, timeout: int = 30) -> Optional[bool]:
    """Whether NVD marks ``cve_id`` as a KEV member (``cisaExploitAdd``).

    Best-effort only — the KEV feed itself is the authoritative source for
    known-exploited status. Returns ``None`` when NVD is unreachable.
    """
    try:
        data = _nvd_request(cve_id, timeout)
        vulns = (data or {}).get("vulnerabilities") or []
        if not vulns:
            return False
        return bool(vulns[0].get("cve", {}).get("cisaExploitAdd"))
    except Exception:
        return None


def fetch_nvd_severity(cve_id: str, timeout: int = 30) -> Optional[dict]:
    """Fetch CVSS for ``cve_id``: prefer v4.0 metrics, fall back to v3.1.

    Returns ``{"baseScore": float, "severity": str}`` (severity uppercased) or
    ``None`` on any failure.
    """
    try:
        data = _nvd_request(cve_id, timeout)
        vulns = (data or {}).get("vulnerabilities") or []
        if not vulns:
            return None
        metrics = vulns[0].get("cve", {}).get("metrics") or {}
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
            metric = (metrics.get(key) or [None])[0]
            if not metric:
                continue
            cvss_data = metric.get("cvssData") or {}
            base_score = cvss_data.get("baseScore")
            severity = cvss_data.get("baseSeverity") or metric.get("baseSeverity")
            if base_score is not None:
                return {
                    "baseScore": float(base_score),
                    "severity": str(severity or "UNKNOWN").upper(),
                }
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# FIRST EPSS (exploitation-probability feed)
# ---------------------------------------------------------------------------


def fetch_epss(cve_ids: List[str], timeout: int = 30) -> Dict[str, dict]:
    """Fetch EPSS scores for ``cve_ids`` (POST batch to api.first.org).

    Returns ``{cve_id: {"epss": float, "percentile": float}}`` for the ids the
    feed knows; ``{}`` on network failure or empty input. Never raises.
    """
    cve_ids = [c for c in (cve_ids or []) if c]
    if not cve_ids:
        return {}
    try:
        body = json.dumps({"cve": cve_ids}).encode("utf-8")
        req = urllib.request.Request(
            EPSS_API_URL,
            data=body,
            headers={
                "Content-Type": "application/json",
                "User-Agent": USER_AGENT,
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
        result = {}
        for row in (data or {}).get("data") or []:
            cve = row.get("cve")
            if not cve:
                continue
            try:
                result[cve] = {
                    "epss": round(float(row.get("epss") or 0.0), 6),
                    "percentile": round(float(row.get("percentile") or 0.0), 6),
                }
            except (TypeError, ValueError):
                continue
        return result
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# Finding -> KEV matching (heuristic, candidate-only enrichment)
# ---------------------------------------------------------------------------


def _entry_matches(finding, entry: dict) -> bool:
    """CWE-id match, or a vulnerability-class keyword hit in the entry name."""
    # 1) CWE equality (finding.cwe == one of the KEV entry's cwes)
    if finding.cwe and any(
        _normalize_cwe(finding.cwe) == _normalize_cwe(c) for c in (entry.get("cwes") or [])
    ):
        return True
    # 2) keyword bridge against the KEV vulnerabilityName
    name = (entry.get("vulnerabilityName") or "").lower()
    keywords = list(KEYWORD_MAP.get(finding.vuln_type, []))
    if finding.vuln_type in GENERIC_KEYWORDS:
        keywords.append(finding.vuln_type.lower())
    if not keywords:
        return False
    return any(keyword and keyword in name for keyword in keywords)


def match_findings_to_kev(findings, kev: Optional[List[dict]] = None) -> List[dict]:
    """Cross-reference findings with the KEV catalog.

    ``kev`` defaults to the cached/fetched KEV catalog. Returns one entry per
    finding that matched at least one KEV record:
    ``{"finding": <Finding>, "kev_cves": [<entry dicts>]}``.

    Heuristic and deliberately conservative — the result enriches *candidates*
    only; it never claims a finding is exploitable.
    """
    if kev is None:
        kev = fetch_kev()
    kev = kev or []
    matches = []
    for finding in findings:
        hits = [entry for entry in kev if _entry_matches(finding, entry)]
        if hits:
            matches.append({"finding": finding, "kev_cves": hits})
    return matches


def kev_enrichment(findings, kev, epss_online: bool = False, epss_timeout: int = 30) -> List[dict]:
    """Annotate findings that match a given KEV snapshot (e.g. from ``--kev-file``).

    Returns one dict per matching finding::

        {"finding": <Finding>, "kev_cves": [cveID, ...],
         "epss": {cveID: {"epss": float, "percentile": float}}}

    EPSS scores are fetched only when ``epss_online`` is True; any network
    failure leaves ``epss`` empty (offline-safe, never raises). Passing an
    empty ``kev`` returns ``[]``.
    """
    kev = kev or []
    enrichment = []
    for match in match_findings_to_kev(findings, kev):
        cves = [e.get("cveID") for e in match["kev_cves"] if e.get("cveID")]
        epss = {}
        if epss_online and cves:
            epss = fetch_epss(cves, timeout=epss_timeout)
        enrichment.append({"finding": match["finding"], "kev_cves": cves, "epss": epss})
    return enrichment
