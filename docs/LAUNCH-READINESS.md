# Launch readiness â€” BlastRadius Agent

Date: **2026-10-24** Â· Commit under review: `1606608` + this change set
Reference basis: `docs/library/MANIFEST.md` (22 free/official sources) and
`docs/library/READING-NOTES.md`.

## Verdict

**Not "perfect" and not production-ready for unattended use.**
It **is** ready for a **supervised beta** (your own repos / authorized CI,
human reviewing every verdict). Treat it as a strong *candidate generator +
prover*, not as an autonomous security authority.

| Launch tier | Ready? | Meaning |
|---|---|---|
| T1 â€” supervised local/CI beta | âœ… **Yes, with the P0 items below scheduled** | Run on owned repos, human triages findings, PR gate advisory or blocking with review |
| T2 â€” public OSS release | âš ï¸ **Almost** | Needs branch protection, a verified release run, and published real-world precision numbers |
| T3 â€” unattended/enterprise | âŒ **No** | Needs independent audit, auth-by-default + rate limits + audit log, multi-language proof, HA/SLA, data-retention policy |

## Evidence snapshot (reproducible)

| Claim | Evidence | Status |
|---|---|---|
| Test suite | `pytest tests/ -q` â†’ **1181 passed, 1 skipped** | âœ… |
| Coverage | measured **85%** (11,981 stmts) | âœ… gate raised 60 â†’ 80 |
| Static benchmark | 16/16, **F1 1.000** (`benchmarks/run.py --verify`) | âœ… corpus is small |
| Dynamic benchmark | 23/23 live checks (`benchmarks/run_dynamic.py`) | âœ… |
| Scale | 10,001 synthetic files: full 30.6 s, PR gate 34.1 s | âœ… synthetic |
| Exploit proof | sandbox fail-closed, `[VULNERABLE]` marker required | âœ… Python PoCs |
| Patch verification | re-run on patched tree, bypass battery | âœ… Python / line-surgical |
| Verified PR gate | missing/unicode base paths fail closed (exit 2 / BLOCK) | âœ… |
| Self-attack | 6 hostile cases + 4 concurrent users, canary isolation | âœ… PASS |
| Wheel | builds (439 KB) + installs in clean venv, CLI works on 3.13 | âœ… |
| Dependency CVEs | project closure (49 pkgs) `pip-audit` â†’ **0 known** | âœ…; now a CI job |
| Workflow pinning | 8 workflows, all `uses:` pinned to commit SHAs | âœ… fixed today |
| Secret scanning | GitHub secret scanning + push protection enabled | âœ… |
| CI matrix | 3.11/3.12/3.13 + **Windows** + pip-audit: all green (`run 40071220312`) | âœ… |
| Branch protection | **enabled**: PR required, linear history, no force-push/delete, 8 required checks, admins enforced | âœ… |
| Real-world study | 20 repos, 182 â†’ 24 candidates (87% removed); **candidate-only, recall unmeasured** | âš ï¸ partial |
| Test suite | **1206 passed, 1 skipped**; ruff clean; benchmark 16/16 F1 1.000 | âœ… |
| Dependabot security updates | **disabled** | âŒ P1 |
| PyPI install | `blastradius-agent` â†’ **404**, name not published | âš ï¸ source install only |
| Container | non-root + healthcheck added; **Docker daemon unavailable â†’ UNVERIFIED** | âš ï¸ |

## P0 â€” must be true before calling it a launch

1. ~~Protect `main`.~~ **Done**: PR required (0 approvals), linear history,
   no force-push/delete, conversation resolution, admins enforced, required
   checks `lint`, `security_scan`, `test (3.11/3.12/3.13)`, `test_windows`,
   `benchmark`, `dependency_audit`, `rules`, `docker`.
2. **Run the release pipeline on a test tag and verify the artifacts**:
   wheel/sdist, CycloneDX SBOM, Sigstore signature, SLSA provenance, and a
   clean-venv install. The workflow exists but has not executed for the
   current code; treat the supply-chain claim as **UNVERIFIED** until then.
   Either publish to PyPI (Trusted Publishing) or remove the implicit
   PyPI-install expectation and document GitHub-release install.
3. **Publish real-world precision/recall.** *Partially done.*
   `docs/REAL-WORLD-STUDY.md` covers 20 repos, a 182 â†’ 24 candidate
   reduction, the false-positive classes fixed, and the scanner performance
   defect. Still missing: a hand-labelled â‰¥100-candidate precision sample
   with a confidence interval, and any measurement of missed classes
   (recall). Until those exist, say "high-signal candidate generator", not
   "low false positives".
4. **Threat-model and test the agent itself.** Prompt injection â†’ tool
   abuse, sandbox escape, path traversal through repo names, API auth
   bypass. We have self-attack, but no independent reviewer. At minimum,
   commission/host a second-party review before T2.
5. **Verify the new CI matrix on GitHub** (Windows + 3.13 + pip-audit).
   It is added but not yet run. A red job is a launch blocker.

## P1 â€” needed for a credible public release

- **Auth by default**: `BLASTRADIUS_API_KEY` unset currently means dev mode;
  require an explicit `--dev` flag, refuse non-loopback bind without a key.
  Add rate limiting + an audit log (ASVS 16.x).
- **Container**: build the main image in CI, run Trivy/Grype, confirm
  non-root + read-only where possible; the Dockerfile change is unverified
  locally.
- **Dependencies**: enable Dependabot security updates, add a lock/constraints
  file for reproducible installs, keep `pip-audit` strict.
- **SAST/fuzzing**: CodeQL (or Semgrep) on `blastradius/`, plus property-based
  tests for parsers (diff scoping, SARIF, patch application).
- **Secret scanning depth**: 5 regex families in the local gate is thin;
  add gitleaks/trufflehog to CI (GitHub push protection already helps).
- **Install story**: publish `blastradius-agent` to PyPI via the existing
  Trusted Publishing path, or make `pipx install git+â€¦` the documented path.
- **Docs site**: Pages is not enabled; the deploy workflow is manual-only so
  `main` stays green. Enable Pages or delete the workflow.
- **PII/data retention**: document what the SQLite DB stores, retention and
  deletion; add optional encryption at rest for API keys/tokens.
- **Supported platforms**: explicitly state Linux/macOS/Windows, Python
  3.11â€“3.13, Docker/gVisor availability, and what degrades without Docker.

## P2 â€” differentiators, not launch blockers

- Multi-language **dynamic** replay (currently Python only; other languages
  stop at candidate / line-surgical verification).
- WSTG coverage matrix for live checks (ATHN/SESS/CRYP/BUSL/CLNT).
- More CWE Top 25 detectors (CSRF, unrestricted upload, deeper authz).
- DeFi: Slither/Foundry/Echidna integration, invariant fuzzing.
- Incremental/cached scanning for monorepos; policy packs; multi-tenant mode.

## Claim matrix (use these words, not stronger ones)

| Marketing phrase | Allowed? | Precise wording |
|---|---|---|
| "19 vulnerability types, 12 languages" | âœ… | static scan surface |
| "proves exploitability in a sandbox" | âš ï¸ | **Python PoCs only**; others are candidates or UNVERIFIABLE |
| "automatically patches" | âš ï¸ | Python AST patches + line-surgical rules; every patch is re-tested |
| "production-ready / enterprise-grade" | âŒ | not until T3 gaps close |
| "SARIF / CI / PR gate" | âœ… | with exit codes 0/1/2 documented |
| "DeFi blast radius" | âš ï¸ | advisory dependency graph + config audit, not a formal audit |
| "zero false positives" | âŒ | no measurement supports it |

## 30-day plan (ordered)

Week 1: branch protection, release dry-run, CI matrix green, auth-by-default.
Week 2: real-world FP/FN study + top FP fixes; publish numbers.
Week 3: container/CI scanning, CodeQL, Dependabot, lockfile.
Week 4: external review + fix; finalize docs, support policy, version 1.2.

**Bottom line:** the engineering core is real (tests, proof, fail-closed,
supply-chain workflow). The missing pieces are *trust* pieces â€” protection,
external measurement, independent review, and operational hardening â€” not
more detectors.

