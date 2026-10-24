# Reading notes → decisions

Full text is in `docs/library/raw/` (gitignored). This page records the
sections that actually changed or validated a decision, not a book report.
Retrieved 2026-10-24.

## 1. OWASP ASVS 5.0 (our own dashboard/API)

Read: V4 API, V6 Authentication, V7 Session, V13 Configuration,
V16 Logging/Error handling, plus the assessment chapter.

| ASVS item | Requirement (paraphrased) | Current state | Decision |
|---|---|---|---|
| 4.1.1 | Correct `Content-Type` + charset on every body | FastAPI sets JSON types; SARIF/comment files are explicit | ✅ verified by API tests |
| 4.1.4 | Only supported HTTP methods | FastAPI router-scoped | ✅ |
| 6.x | Auth is a real control, not a warning | `BLASTRADIUS_API_KEY` optional → **dev mode without auth**; dashboard token only on mutating routes | ⚠️ **P1**: add `--dev` explicit flag, refuse unauthenticated non-loopback bind |
| 7.x | Session lifetime / concurrency documented | No user sessions (API key / local token) | ✅ N/A, document it |
| 13.1.4 | Secrets inventory + rotation schedule | `.env`-based, documented in `.env.example`; no rotation doc | ⚠️ P1: secrets inventory section in SECURITY.md |
| 16.1.1/16.2.x | Log inventory, UTC, no secret leakage | Structured console logs; secret-redaction tests exist; no audit-log table | ⚠️ P1: audit log for scan/patch actions, UTC timestamps |

Also relevant: ASVS explicitly separates *verification levels*; we should
state our own level (L1/L2) rather than imply "ASVS compliant".

## 2. OWASP WSTG (dynamic coverage map)

Read: category index + injection/authz/session/API sections.

- WSTG categories: INFO, CONF, IDNT, ATHN, ATHZ, SESS, INPV, ERRH, CRYP,
  BUSL, CLNT, APIT.
- Our live scanner covers a slice: reflected XSS, open redirect, headers,
  CORS, exposed files, directory listing, takeover fingerprint, plus opt-in
  IDOR/JWT/SSRF/GraphQL/smuggling modules.
- **Gap:** no live ATHN/SESS/CRYP/BUSL/CLNT equivalents in the default path.
  Do **not** market as "full WSTG". Roadmap item P2: publish a coverage
  matrix with tested/not-tested per category.

## 3. OWASP Top 10:2025, API Top 10:2023, LLM Top 10

- Note: OWASP Top 10 **2025** is current; our docs/benchmarks must not cite
  2021 as "latest".
- API Top 10 2023 is still the current API edition (BOLA #1). Our static
  IDOR detector + live 2-identity module are the relevant controls; the
  **live** path is not default-on.
- LLM Top 10 grounds the AI-review surface: prompt injection, insecure
  output handling, excessive agency. Our AI review is advisory; the policy
  engine is deterministic (good), and provider responses are grounded
  against the ChangeSet (verified by tests).

## 4. NIST SSDF SP 800-218 / 800-218A (SDLC)

47 practices extracted (PO/PS/PW/RV). Mapping that matters:

| Practice | What we have | Gap |
|---|---|---|
| PO.1 / PO.2 | `SECURITY.md`, threat notes, rules | No formal risk register |
| PS.1 / PS.2 | MIT license, DATA_ATTRIBUTION, provenance in release | Third-party corpus licenses need a review note |
| PS.3 | SBOM + Sigstore + SLSA provenance workflow | Flow has not run for a new tag since these changes |
| PW.4 / PW.5 | Code review rules, secret scanning | Branch protection is **off** (GitHub API 404) |
| PW.6 | CI matrix, lint, tests, benchmarks | Windows job missing until now |
| PW.7 / PW.8 | Self-attack, adversarial tests, sandbox | No fuzzing / property-based tests |
| RV.1 | CVE/KEV/EPSS + pip-audit in CI (added) | No external vulnerability intake/SLA |
| RV.2 | Patch loop + re-test | Non-Python replay is unimplemented |

SP 800-218A: AI-generated patches are verified by execution before being
reported as fixed (`exploit-replay`), which is the profile's core ask; keep
the "candidate vs proven" distinction explicit.

## 5. CISA secure supply chain (developers)

Key asks: protect the build environment, produce provenance, know your
dependencies, harden the pipeline.

- Have: pinned tool versions in release notes, SBOM generation,
  Trusted Publishing, Sigstore/SLSA attestation, CycloneDX validation.
- Added today: **all GitHub Actions pinned to commit SHAs** (was mixed
  tags/SHAs), **pip-audit CI job**, **coverage gate 80% (actual 85%)**,
  **3.13 in the test matrix**, **Windows CI job**.
- Still missing: container image scanning/signing (the main image is not
  built in CI), Dependabot security updates are **disabled**.

## 6. OpenSSF Scorecard / Best Practices badge

Checks reviewed: Pinned-Dependencies, Dangerous-Workflow, Token-Permissions,
Branch-Protection, Code-Review, CI-Tests, SAST, SBOM, Signed-Releases,
Security-Policy, Dependency-Update-Tool, Fuzzing, Packaging.

| Check | State |
|---|---|
| Pinned-Dependencies | ✅ fixed today (8 workflows) |
| Token-Permissions | ✅ mostly explicit; verify per-workflow least privilege |
| Branch-Protection | ❌ not enabled |
| Code-Review | ❌ no required review on `main` |
| SAST | ⚠️ Bandit only; no CodeQL/Semgrep in CI |
| SBOM | ✅ release workflow |
| Signed-Releases | ✅ Sigstore + SLSA workflow (unverified for a new tag) |
| Dependency-Update-Tool | ❌ Dependabot security updates disabled |
| Fuzzing | ❌ none |
| Security-Policy | ✅ SECURITY.md with 90-day disclosure |
| Packaging | ✅ wheel builds and installs in a clean venv |

## 7. SARIF 2.1.0 / CycloneDX 1.6 / SLSA 1.0

- SARIF: our exporter is tested; keep `security-severity` as a string (a
  real bug found in beta) and validate against the schema in CI if a schema
  copy is available offline.
- CycloneDX: `verify_release.py` validates structure + purls before attach.
- SLSA: the release workflow *claims* provenance; the claim is only real
  after a tag run, and should be verified consumer-side (`slsa-verifier`)
  in docs.

## 8. CWE Top 25 (2024)

Coverage in `hunter/scanner.py` + `scanners/` is strongest for injection
classes (CWE-79/89/78/94/22/918/502), and weakest for:
- CWE-352 CSRF (no dedicated detector),
- CWE-434 unrestricted upload (no static rule),
- CWE-862/863 missing authorization beyond the IDOR heuristic,
- CWE-798 hardcoded credentials (covered, but only high-signal patterns),
- CWE-1104 outdated components (delegated to SCA; no gate by default).

Do not claim "Top 25 coverage" without a per-CWE test matrix.

## 9. DeFi sources (Trail of Bits, Solidity docs, ConsenSys, Foundry)

- Confirms our config-auditor rules (DVN redundancy, threshold reachability,
  admin multisig/timelock, oracle single-feed) map to known incident classes.
- Confirms the static Solidity detector is a *candidate generator*: real
  audits need AST/call-graph (Slither) + tests. We already label it that way.
- Gap: no formal invariant/fuzz testing (Echidna/Foundry) integration.

## 10. Google SRE security book

- Least privilege, explicit trust boundaries, graceful degradation, and
  "design for failure" support the fail-closed decisions (unknown base ref →
  error, unprovable finding → candidate, sandbox unavailable → no proof).
- It also argues against silent fallbacks — exactly the two fail-opens the
  self-attack found today. Keep the self-attack as a release gate.
