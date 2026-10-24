# Reference library — sources used for launch readiness

Retrieved **2026-10-24**. Raw files live in `docs/library/raw/` (gitignored, large).
Re-fetch with `python scripts/fetch_reference_library.py`.

**What this is not:** a pirated book dump. Paywalled/classic titles
(*The Web Application Hacker's Handbook*, *The Tangled Web*, *Real-World Bug
Hunting*, *Black Hat Python*, *Hacking: The Art of Exploitation*) are
deliberately **not** downloaded — they are copyrighted and not freely
redistributable. Where a free, official edition exists, that is what is
stored. Everything below is public standards/guidance or freely published
material; redistribution terms are noted so we do not commit the raw files.

| # | Source | Edition / date | File | Terms (see source) | Why it matters here |
|---|--------|----------------|------|--------------------|---------------------|
| 1 | OWASP Top 10 | 2025 | `owasp-top10-2025.html` | CC BY-SA 4.0 | Web risk baseline; note 2021 edition is superseded |
| 2 | OWASP API Security Top 10 | 2023 | `owasp-api-top10-2023.html` | CC BY-SA 4.0 | BOLA/BFLA/API authz — maps to static IDOR + live gaps |
| 3 | OWASP LLM Top 10 | current | `owasp-llm-top10.html` | CC BY-SA 4.0 | AI-assisted review, prompt-injection handling |
| 4 | OWASP ASVS | 5.0 | `owasp-asvs.zip`, `raw/asvs-5.0/*.md` | CC BY-SA 4.0 | Verification requirements for our own dashboard/API |
| 5 | OWASP WSTG | current | `owasp-wstg.zip`, `raw/wstg/*.md` | CC BY-SA 4.0 | Test coverage map for dynamic checks |
| 6 | OWASP SAMM | current | `owasp-samm.html` | CC BY-SA 4.0 | Security-program maturity framing |
| 7 | NIST SP 800-115 | 2008 | `nist-sp800-115.pdf` | US Gov / public domain | Technical security testing methodology |
| 8 | NIST SSDF SP 800-218 | v1.1 | `nist-sp800-218.pdf` | US Gov / public domain | Secure SDLC practices (PO/PS/PW/RV) |
| 9 | NIST SSDF AI profile SP 800-218A | 2024 | `nist-sp800-218a.pdf` | US Gov / public domain | AI-generated code risks |
| 10 | CISA secure software supply chain (developers) | 2023 | `cisa-sscs-developers.pdf` | US Gov / public domain | Build/release hardening |
| 11 | CWE Top 25 | 2024 | `cwe-top25-2024.html` | MITRE terms (free, attribution) | Detection-coverage checklist |
| 12 | SARIF | 2.1.0 OASIS | `sarif-2.1.0.html` | OASIS (free to read) | Our SARIF export correctness |
| 13 | SLSA | v1.0 | `slsa-1.0.html` | see slsa.dev | Provenance level claims |
| 14 | OpenSSF Scorecard checks | main | `scorecard-checks.md` | Apache-2.0 | Repo security scorecard |
| 15 | OpenSSF Best Practices badge criteria | current | `openssf-badge-criteria.html` | free to read | Release hygiene checklist |
| 16 | CycloneDX | 1.6 | `cyclonedx-1.6.html` | Apache-2.0 | SBOM schema |
| 17 | The Twelve-Factor App | 2017 | `12factor.html` | MIT | Deploy/config/logs discipline |
| 18 | Trail of Bits — Building Secure Contracts | current | `tob-secure-contracts.html` | see secure-contracts.com | DeFi audit methodology |
| 19 | Solidity security considerations | latest | `solidity-security.html` | see docs.soliditylang.org | Smart-contract detector grounding |
| 20 | ConsenSys Diligence best practices | current | `consensys-best-practices.html` | see repo | Solidity patterns |
| 21 | Foundry Book | current | `foundry-book.html` | see book.getfoundry.sh | Test/PoC tooling for contracts |
| 22 | Google — Building Secure & Reliable Systems | free online | `google-sre-security.html` | CC BY-NC-ND (site) | Security/reliability engineering practices |

## Not available / intentionally omitted

- **PTES Technical Guidelines** — `pentest-standard.org` did not respond
  (HTTP/HTTPS timeout) on 2026-10-24. WSTG covers the same ground for our
  purposes.
- **OWASP Top 10:2021** — the site now redirects to the 2025 edition; the
  current edition is stored instead.
- **CISA HTML landing page** — 404; the PDF above is the real document.
- **Paywalled books** — not downloaded; see note at the top.

## How the library is used

`docs/library/READING-NOTES.md` records the specific sections that drove
concrete decisions, and `docs/LAUNCH-READINESS.md` turns them into a
verdict + prioritized gaps. Raw text stays out of git because of size and
because several sources are share-alike / non-commercial.
