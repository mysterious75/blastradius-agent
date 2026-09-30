# IMPROVEMENTS — what changed + roadmap

Date: 2026-09-26 · base commit `13e6a68` · all changes verified offline + live.

## Summary
Three steps: (1) prove the repo's health, (2) gap-analyse it vs our hunting catalogs,
(3) ship the highest-value missing capability. Result: **1 real bug fixed, 1 missing dep
declared, 1 new live security check added, 13 new tests, 0 regressions.**

---

## Step 1 — Test-suite health
- `pip install -e ".[all]"` + `pyyaml` (the latter was **missing from deps** though
  `tests/test_release*.py` import it → collection error on a clean install).
- Baseline before my code: **678 passed, 1 failed, 1 skipped**.
- **Bug found + fixed:** `Deduplicator.get_tracking_rows()` ordered only by
  `disclosed_at DESC`; two rows disclosed in the same second tied and returned
  non-deterministically → `test_tracking_rows_and_stats` failed. Fix: stable
  tiebreaker `ORDER BY t.disclosed_at DESC, t.finding_id ASC`
  (`blastradius/db/deduplicator.py`).
- After: **679 passed, 1 skipped, 0 failed**.

## Step 2 — Gap analysis (`GAP_ANALYSIS.md`)
- Inventoried the repo: **static** engine `CVEHunter` = **19 vuln types** (incl. idor,
  jwt, graphql) + `scanners/` = 13 self-contained scanners; **dynamic** `web/scanner.py`
  = only 7 checks.
- Corrected my own first-pass error: IDOR **is** covered *statically* (`_scan_idor` +
  sandbox PoC). The real gap is **dynamic/live**.
- **Headline gap:** the repo cannot *test a running target* for the classes it detects
  in source — no live IDOR/SSRF/XXE/SQLi/JWT/authz; no live 2-identity diff; no
  blind→oracle; no chains.

## Step 3 — Shipped improvement: live IDOR/BOLA authz-diff

### New code
| File | What |
|---|---|
| `blastradius/web/authz.py` | `AuthzDiffChecker` + `AuthzFinding`: replay victim object URLs under an attacker session; flag cross-identity reads (marker-based = 0.95, byte-identical = 0.75); denial-regex + status guards; read-only, bounded. |
| `blastradius/web/scanner.py` | Wired `authz` + `authz_urls` into `DynamicWebScanner`; new `_check_authz()`; new `idor CWE-639` check in docs. |
| `blastradius/web/browser.py` | Added `default_headers` (backward-compatible) so identity cookies reach each request. |
| `blastradius/web/cli.py` | Opt-in flags `--attacker-cookie`, `--victim-cookie`, `--victim-marker`, `--idor-url`. |
| `demos/idor_demo_server.py` | Live demo target (vulnerable + safe endpoint). |
| `scripts/smoke_idor_live.py` | Live end-to-end smoke test. |
| `tests/test_web_authz.py` | 13 offline tests (candidate selection, diff logic, scanner integration, default headers). |

### Verification
- Unit: `tests/test_web_authz.py` **13 passed**.
- Suite: **692 passed, 1 skipped, 0 failed** (was 678/1/1 at baseline).
- Benchmark: **F1 = 1.000 (15/15)** — no regression.
- **Live proof** (`scripts/smoke_idor_live.py`): flags `/api/user/2` (IDOR, HIGH 0.95),
  correctly does **not** flag `/api/safe/2` (ownership enforced). CLI path verified too
  (`idor | 0.95 | HIGH` appears in the findings table).

### Design principles honoured
- **Opt-in** — inert unless two identity sessions are supplied (no accidental scanning).
- **Read-only** — GET replay only; never write methods.
- **No fabricated requests** — replays only crawler-discovered or user-provided URLs.
- **Evidence-first** — finding carries the exact victim-marker/body evidence.
- **Offline tests** — duck-typed sessions, zero network.

---

## Roadmap (next highest-value increments)
1. **Live SSRF + blind→oracle check** — mirror the Faav playbook: inject into URL params,
   detect OOB callback / timing / redirect-follow; the repo has static SSRF only.
2. **Live JWT check** — `alg:none`, RS256→HS256 confusion, `kid` traversal (static `jwt`
   type exists; no live probe).
3. **Chains** — express A→B→C (open redirect→OAuth, IDOR→ATO) as first-class graph output
   instead of single-line findings.
4. **Mass-assignment live check** — send privileged fields (`role`, `is_admin`, `tenant_id`)
   on profile/update endpoints; diff the returned object.
5. **Benchmark corpus for dynamic checks** — seed from our real-target findings
   (Infomaniak/Neon) so the dynamic layer is gated like the static one.
6. **Field-name/type abuse** — port the Faav §3 "don't trust the field name" probes.
7. **Declare `pyyaml` in `[dev]` extras** (or core) to fix clean-install collection.

## Files changed
```
blastradius/db/deduplicator.py      (bug fix)
blastradius/web/authz.py            (new)
blastradius/web/scanner.py          (integration)
blastradius/web/browser.py          (default_headers)
blastradius/web/cli.py              (flags)
demos/idor_demo_server.py           (new)
scripts/smoke_idor_live.py          (new)
tests/test_web_authz.py             (new)
README.md                           (docs)
GAP_ANALYSIS.md, IMPROVEMENTS.md    (new)
```

---

## Session 2 — merged 6-item patch (2026-09-30, each item researched first)

Research done per item: PyPA/pytest packaging conventions (pyyaml), repo data-file
conventions (token_backing), ZAP default-deny + OWASP APTS pre-action validation
(scope gates), precise registry counts via import (docs).

| # | Change | Files | Tests |
|---|---|---|---|
| 1 | `pyyaml>=6.0` → `[dev]` extras | `pyproject.toml` | yaml test modules collect+pass |
| 2 | `_TOKEN_BACKING` → `data/token_backing.json` (+ loader fallback) | `data/token_backing.json`, `loaders/snapshot.py` | 4 new (sync/file/override/fallback) |
| 3 | Scope gates on all 6 URL CLIs (`hunter` refactor to shared `require_scope()`; `web`, `recon` filter, `auto_hunt`, `agents`, `pipeline`) | `scope.py`, 6 CLIs, `recon/auto_hunt.py` | 9 new (`test_scope_gates.py`) |
| 4 | Modules stay in `web/` — verified placement, no move | — | — |
| 5 | Doc numbers: README/AGENTS 8→18, CHANGELOG Unreleased note | `README.md`, `AGENTS.md`, `CHANGELOG.md` | parity tests |
| 6 | `_title()` missing `secret` → `"Hardcoded Secret"` | `hunter/scanner.py` | `test_registry_parity.py` (4) |

Health after session 2: **739 passed, 1 skipped, 0 failed** (was 722) · benchmark **F1=1.0 (15/15)**.

---

## Session 3 — Aave loader + dynamic benchmark + v1.1.0 + lint (2026-09-30)

Research-first per item (Aave docs/GraphQL introspection, ZAP+OWASP scope patterns,
PyPA conventions, registry counts via import).

| Item | Result |
|---|---|
| Aave loader (`contagion/loaders/aave.py`) | keyless AaveKit GraphQL, schema mapped by introspection; live cross-check 6 markets/126 reserves → 38 collateral + 38 oracle edges; 8 tests |
| Dynamic benchmark (`benchmarks/run_dynamic.py` + 3 live targets) | F1=1.0 ×3 runs, deterministic; CI gate added to `ci.yml` |
| Release v1.1.0 | version bump (single-sourced), CHANGELOG entry, tag pushed (release workflow running); version-agnostic test fixes |
| Lint | own new files ruff-clean (UP035/F401/BLE001-noqa/S110); repo-wide 1241 pre-existing violations untouched (upstream debt) |

Health after session 3: **755 passed, 1 skipped, 0 failed** · static F1=1.0 · dynamic F1=1.0.
