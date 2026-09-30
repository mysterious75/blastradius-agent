"""Offline tests for exploit-chain linking."""

from blastradius.web.chains import Chain, build_chains, combined_severity


class F:
    def __init__(self, check, url="https://x/y", severity="MEDIUM"):
        self.check = check
        self.url = url
        self.severity = severity


def test_open_redirect_to_oauth_chain():
    findings = [F("redirect"), F("oauth")]
    chains = build_chains(findings)
    names = {c.name for c in chains}
    assert "Open redirect -> OAuth code theft" in names
    c = next(c for c in chains if "OAuth" in c.name)
    assert c.severity == "CRITICAL" and c.steps == ["redirect", "oauth"]


def test_idor_to_ato_chain():
    chains = build_chains([F("idor"), F("ato")])
    assert any(c.severity == "CRITICAL" for c in chains)


def test_ssrf_to_metadata_chain():
    chains = build_chains([F("ssrf"), F("cloud-metadata")])
    assert any("metadata" in c.name and c.severity == "CRITICAL" for c in chains)


def test_blind_ssrf_oracle_chain():
    chains = build_chains([F("ssrf-oracle"), F("cloud-metadata")])
    assert any(c.severity == "HIGH" for c in chains)


def test_no_chain_without_all_steps():
    assert build_chains([F("redirect")]) == []
    assert build_chains([F("idor")]) == []


def test_empty_findings():
    assert build_chains([]) == []


def test_combined_severity_picks_highest():
    assert combined_severity([F("x", severity="LOW"), F("y", severity="CRITICAL")]) == "CRITICAL"
    assert combined_severity([]) == "INFO"


def test_vuln_type_attribute_supported():
    class G:
        vuln_type = "jwt-none"
        url = "https://x/j"
        severity = "CRITICAL"

    chains = build_chains([G(), F("idor")])
    assert any("JWT" in c.name for c in chains)


def test_chain_describe():
    c = Chain(name="A -> B", severity="HIGH", steps=["a", "b"])
    assert c.describe() == "A -> B: a -> b"
