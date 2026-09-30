# GAP ANALYSIS — blastradius-agent scanners vs our hunting catalogs

Date: 2026-09-26 · Baseline: `blastradius-agent` @ 13e6a68 (679 tests pass, 1 skipped)
Method: inventory repo detection surface → map against `D:\deepseek` hunting assets → find gaps.

---

## 1. Two different layers (the key framing)

| | blastradius-agent | our workspace |
|---|---|---|
| **Where it looks** | **source code of a repo** (static) + a little live HTTP probing | **live running targets** (runtime) |
| **When** | pre-merge / pre-deploy | during a bug-bounty hunt |
| **Proof** | sandbox `[VULNERABLE]` marker (executes a PoC) | real cross-account / OOB / timing PoC |
| **Unit** | line-of-code finding | endpoint + request + response |

**They are complementary, not competitors.** The repo's static scanners *find* suspicious code; our catalogs *exploit* live behavior. The gap is where the two must meet: **dynamic (live-target) tests for classes the repo's `web/scanner.py` does not cover.**

---

## 2. Repo detection surface (what exists today)

### 2a. Static scanners — TWO layers
**(i) `CVEHunter` (`hunter/scanner.py`) — 19 vuln types** incl. **`idor`** (function-level object-id + no-auth reasoning, multi-language), `jwt`, `graphql`, `ci_injection`, `secret_history`, plus the 8 core. This is the primary static engine and it DOES cover IDOR + JWT + GraphQL statically.

**(ii) `scanners/` package — 14 self-contained scanners** (`auth_bypass, cmd_injection, crlf, deserialization, nosqli, proto_pollution, secrets, solidity, sqli, ssrf, ssti, traversal, xss, xxe`). Regex line scan + `has_source`/`references_variable` reasoning + `_SAFE` suppression + confidence.

`SolidityScanner` is the only non-web-shaped member: `*.sol` is registered in
`FILE_EXTENSIONS` and `CVEHunter._scan_file` dispatches to it before the generic
line scorers, because those are indentation/string-literal heuristics that misfire
on contract source. It adds structural checks (function-block reentrancy) on top of
the line rules, and a `.sol` ground-truth case sits in the benchmark corpus.

**Gap that remains:** Slither-grade precision (AST + call-graph, false-positive
suppression via `reentrancy-eth`, `send`, `solhint` config) is not reproduced. The
current detector is a high-signal candidate generator, so an analyst/sandbox stage
must confirm before any finding is called proven.

> Correction: an earlier draft of this doc said "no IDOR scanner" — that was wrong. IDOR is covered **statically** in `CVEHunter._scan_idor` (+ an IDOR sandbox PoC). The real gap is the **dynamic/live** side.

### 2b. Dynamic web scanner (`blastradius/web/scanner.py`)
Only 7 checks: **reflected XSS, open redirect, security headers (CSP/HSTS/XFO/XCTO), CORS wildcard+credentials, exposed files (.git/.env/admin), directory listing, subdomain-takeover fingerprint.**

### 2c. Other
`contagion/` (DeFi pre-deploy graph + config auditor), `blast_radius/` (package→repo), `sca.py`/`osv_check` (deps), `taint.py`, `rules.py` (YAML custom rules), `payloads.py` (H1 payload corpus loader — XSS/SQLi/command only).

---

## 3. GAP TABLE — our catalog technique vs repo coverage

Legend: ✅ covered · ⚠️ partial · ❌ missing

| Our asset / technique | Repo static | Repo dynamic | Gap |
|---|---|---|---|
| **IDOR / BOLA (2-account)** `IDOR_CATALOG.md` (40 tamper methods) | ✅ `_scan_idor` (function-level) | ❌ | **static yes; no LIVE 2-identity diff** |
| **20+20 ID-tamper catalog** (ref-shape/parser/route/header) | ⚠️ basic id-source only | ❌ | missing tamper variants |
| **Cross-tenant** (tenant mismatch, sub-resource, async worker) `METHODOLOGY.md` | ❌ | ❌ | missing |
| **Blind BOLA** (export/email/async) | ❌ | ❌ | missing |
| **SSRF** `XXE_PASS_RESULTS` + `hunt-ssrf` | ✅ static sink | ❌ dynamic | no live SSRF probe / OOB |
| **Blind SSRF → oracle** (Faav timing/redirect-follow) | ❌ | ❌ | **missing — our proven technique** |
| **Secondary-context traversal** `..%2f` (Faav) | ⚠️ static sinks | ❌ | no live traversal probe |
| **SQLi** `hunt-sqli` | ✅ static | ❌ dynamic | no live SQLi (error/bool/time) |
| **NoSQLi** `$gt/$where` | ✅ static | ❌ | no live NoSQLi |
| **XXE** `XXE_CATALOG` | ✅ static | ❌ | no live XXE/OOB |
| **Auth bypass** (forced-browse, param tamper, session prediction) | ⚠️ static | ❌ | no live authz diff |
| **JWT alg:none / confusion** (Faav Titan) | ❌ | ❌ | missing |
| **JWT `upn`≠UPN field-name abuse** (Faav) | ❌ | ❌ | missing |
| **Open redirect** | ❌ static | ✅ dynamic | ✅ (only redirect itself) |
| **Open redirect → OAuth/SSRF chain** | ❌ | ❌ | missing chain |
| **JS-source secret + hidden endpoint** (Faav #1) | ✅ `secrets` scanner | ❌ | static only; no live JS-bundle fetch/parse |
| **OData/GraphQL injection** | ❌ | ❌ | missing |
| **Mass assignment** (role/isAdmin) `mass-assignment` | ❌ | ❌ | missing |
| **Stored XSS via secondary render** (Faav notification) | ⚠️ xss static | ⚠️ reflected only | no stored/stored-via-notification |
| **Cache poisoning / WCD** | ❌ | ❌ | missing |
| **HTTP smuggling** | ❌ | ❌ | missing |
| **CSRF / SameSite** | ❌ | ❌ | missing |
| **Race / TOCTOU** | ❌ | ❌ | missing |
| **MFA bypass** | ❌ | ❌ | missing |
| **Subdomain takeover** | ⚠️ fingerprint | ✅ | partial |
| **CORS** | ❌ | ✅ | ok |
| **GraphQL audit** | ❌ | ❌ | missing |
| **Field-name/type confusion** (Faav §3) | ❌ | ❌ | missing |
| **Parser disagreement** (route/query/body) | ❌ | ❌ | missing |

---

## 4. Headline gaps (ranked by impact to the product)

1. **Dynamic layer is thin (7 checks)** — the repo's static engine is broad (19 types) but `web/scanner.py` only does reflected XSS / open redirect / headers / CORS / exposed files / listing / takeover. **No live IDOR/SSRF/XXE/SQLi/JWT/authz** — i.e. it cannot *test a running target* for the classes it *detects in source*. ← **#1 gap; our catalogs + Faav playbook fill it.**
2. **No live 2-identity authz diff** — static `_scan_idor` finds suspicious code; nothing *proves* IDOR against a live API with attacker/victim tokens. Our `METHODOLOGY.md` (2-account) is the blueprint.
3. **No blind→oracle reasoning in dynamic tests** — repo "prove" stops at sandbox; our timing/redirect/OOB oracle patterns (Faav) are absent from live checks.
4. **No chains** — findings are single-line (file-based "chains" only); our A→B→C (open redirect→OAuth, SSRF→metadata, XSS→ATO) is absent.
5. **Payload corpus narrow at runtime** — `payloads.py` only XSS/SQLi/command; our IDOR/SSRF/XXE/OData/NoSQL/JWT/traversal payloads add live coverage.
6. **Static misses some modern classes** — mass-assignment, field-name abuse, parser-disagreement, cache/smuggling/race/CSRF/MFA (our catalogs).

---

## 5. What the repo does *better* than us

- **Execution-proof discipline** (`[VULNERABLE]` marker, fail-closed sandbox) — we assert in prose.
- **Auto-patch + verify loop** — we don't patch.
- **CI/benchmark gate** (F1 corpus) — we have no regression benchmark.
- **Packaging/infra** (Docker, MCP, dashboard, SARIF/SBOM, PR gate).
- **Corpora** — 14,833 H1 reports + Bugcrowd verified + ground-truth benchmark.
- **Research/positioning** — competitive dossier + valuation + gap analysis.

---

## 6. Verdict

The repo is a **mature static+light-dynamic product**; our workspace is a **runtime hunting brain**. The single highest-value synthesis:

> **Port our catalog + Faav methodology into the repo's dynamic layer as first-class checks**, and port the repo's "prove/gate" discipline into our hunting workflow.

Concrete build targets (Step 3): an `IDORScanner` (static hints) + a `blastradius/web` extension with **authz-diff (2-identity), SSRF-oracle, traversal, SQLi-live, JWT, mass-assignment, chain** checks, backed by our payload catalogs and a new benchmark corpus seeded from our findings.
