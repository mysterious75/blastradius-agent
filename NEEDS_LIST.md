# NEEDS LIST — do parallel tracks (Product moat + Weaponize)

Date: 2026-09-26 · Status: **both tracks started, data downloaded, first modules shipped**

Two goals:
- **Track A — Product moat:** DeFi Dependency Graph (the data asset nobody sells).
- **Track B — Weaponize:** put our hunting modules (live SSRF→oracle, JWT, chains)
  into the repo so it can test *live* targets, not just source.

---

## 0. What I already downloaded (all free/public, no key) — DONE

Location: `data/ingest/` (~28 MB) + cloned corpora.

| File / dir | Size | Source | Used for |
|---|---|---|---|
| `defillama_protocols.json` | 8.6 MB | api.llama.fi/protocols | protocol → chains + TVL (8,382 protocols) |
| `defillama_pools.json` | 11.2 MB | yields.llama.fi/pools | pool exposure (17,131 pools) |
| `defillama_lendborrow.json` | 0.8 MB | yields.llama.fi/lendBorrow | real supply/borrow/LTV (2,459 markets) |
| `chainlink_feeds_mainnet.json` | 0.38 MB | reference-data-directory | 298 oracle feeds (pair → proxy) |
| `feeds-bsc-mainnet.json` | 0.22 MB | reference-data-directory | BSC feeds |
| `pyth_price_feeds.json` | 0.15 MB | hermes.pyth.network | Pyth feeds |
| `layerzero_metadata.json` | 4.0 MB | metadata.layerzero-api.com | chains, deploys, DVNs |
| `layerzero_deployments.json` | 1.0 MB | metadata.layerzero-api.com | per-chain endpoints/DVNs |
| `layerzero_ofts.json` | 0.8 KB | metadata.layerzero-api.com | OFT bridge token edges |
| `morpho_blue_markets.json` | 44 KB | api.morpho.org | lending markets + oracle |
| `fluid_vaults_eth.json` | 0.68 MB | api.fluid.instadapp.io | vault collateral/borrow pairs |
| `chainid_chains.json` | 1.2 MB | chainid.network | chain → RPC list |
| `defihacklabs-incidents/` | 1.5 MB | github SunWeb3Sec | **960 incidents** + 797 root-causes |
| `defi-hack-chronicle/` | — | github DeFiHackLabs | 25 structured incident JSONs |

Downloaders: `scripts/probe_defi_sources.py`, `scripts/download_defi_data.py`.

---

## 1. Track A — shipped

- `blastradius/contagion/loaders/snapshot.py` — **offline** graph builder from
  `data/ingest/*.json`; adds the edge types the live loader lacked:
  - `PRICES` (Oracle→Token) — Chainlink + Pyth (721 edges on real data)
  - `BACKS` (Token→Token) — LRT/LST nesting (weETH→eETH, wstETH→stETH, …)
  - multi-chain `DEPLOYED_ON`; Morpho markets with collateral + oracle edges
- `tests/test_contagion_snapshot.py` — 7 tests (offline + real-snapshot smoke).
- Real build: **1,273 nodes / 2,232 edges** (433 Token, 425 Oracle, 215 Chain, 200 Protocol).

## 2. Track B — shipped

| Module | File | Tests | What |
|---|---|---|---|
| Live SSRF→oracle | `web/ssrf.py` + `web/oob.py` | 6 | OOB callback injection, redirect-follow bypass, iPad oracle semantics |
| Live JWT | `web/jwt.py` | 8 | alg:none, RS256→HS256 confusion, weak secret, kid traversal, hygiene |
| Chains | `web/chains.py` | 9 | A→B→C rules (redirect→OAuth, IDOR→ATO, SSRF→metadata, JWT→IDOR…) |
| Live IDOR (earlier) | `web/authz.py` | 13 | 2-identity authz diff |

Wired into `web/cli.py`: `--attacker/victim-cookie`, `--victim-marker`, `--idor-url`,
plus exploit-chain reporting in the findings output + JSON.

---

## 3. NEEDS LIST — what still requires action

### 3a. Data still to collect (Track A) — I can auto-download these
| Need | Source | Auth | Why |
|---|---|---|---|
| **Aave V3/V4 reserves** | `POST https://api.v3.aave.com/graphql` (markets/reserves) | none | canonical collateral listings + LTV + oracle addr |
| **SparkLend / Compound configs** | on-chain via public RPC (`getReservesData`) | none | more lending markets |
| **LayerZero DVN per-oApp config** | `scan.layerzero-api.com/v1/messages/...` | none | DVN redundancy edges (KelpDAO class) |
| **Backstop buffers (Aave Umbrella, safety modules)** | on-chain reads via RPC | none | fix the `backstop_buffer_usd=0` upper-bound gap |
| **Token nesting (full LRT composition)** | on-chain `getRate()` (weETH/rsETH/…) | none | precise `BACKS` edges |
| **DeFiLlama hacks** | Pro API (key) `pro-api.llama.fi/{KEY}/api/hacks` | **key (paid)** | structured hack dataset (**optional** — we have DeFiHackLabs 960) |

### 3b. Code still to build
| Item | Track | Priority |
|---|---|---|
| Aave/SparkLend loader (GraphQL + on-chain) into `snapshot` | A | HIGH |
| DVN config auditor integration (feed LayerZero metadata → `config_audit`) | A | HIGH |
| Backstop-buffer on-chain reader (removes the upper-bound caveat) | A | MEDIUM |
| `scripts/ingest_snapshot.py` CLI (build `docs/data/blast-graph.json` from snapshot) | A | MEDIUM |
| Live SQLi / NoSQLi / traversal dynamic checks | B | MEDIUM |
| Mass-assignment live check (role/is_admin/tenant_id) | B | MEDIUM |
| Field-name/type abuse probes (Faav §3) | B | LOW |
| OOB listener wired to interactsh/webhook.site for real targets | B | MEDIUM |
| Dynamic benchmark corpus (gate the new live checks) | B | HIGH |
| `pyyaml` declared in deps (clean-install gap) | infra | LOW |

### 3c. External assets/accounts needed from you
| Need | Why | Blocking? |
|---|---|---|
| **Public OOB service** (webhook.site token / interactsh) — we already have a webhook.site token | real SSRF callback from the *target* network | no — token exists |
| **Two test accounts** on any live target (attacker+victim cookies) | live IDOR/authz diff | yes for live IDOR |
| **Free public RPC** (PublicNode/LlamaRPC/dRPC) | on-chain reads for Aave/DVN/backstop | no — keyless |
| *(optional)* DeFiLlama **Pro key** | `/api/hacks` structured data | no — we have DeFiHackLabs |
| *(optional)* Graph **free API key** | subgraph queries | no — GraphQL endpoints keyless for Aave/Morpho |

---

## 4. Roadmap (ordered by ROI)

1. **Aave/SparkLend loader** → real collateral listings into the graph (Track A core).
2. **Dynamic benchmark corpus** → gate the 4 new live checks like the static F1 gate.
3. **SSRF→oracle live end-to-end** against a demo server + real OOB (webhook.site).
4. **DVN config auditor** fed by LayerZero metadata (the KelpDAO $292M class).
5. **Backstop on-chain reader** → remove the documented upper-bound caveat.
6. **Live mass-assignment + SQLi checks** → round out the dynamic layer.
7. **`ingest_snapshot.py`** → publish `docs/data/blast-graph.json` with provenance for the public calculator.

## 5. Current health
- Suite: **722 passed, 1 skipped, 0 failed** (baseline was 678/1/1).
- Benchmark: **F1 = 1.000 (15/15)** — no regression.
- New tests this session: **43** (7 contagion + 6 SSRF + 8 JWT + 9 chains + 13 authz).
- Bug fixes: 2 (dedup ordering flake; missing pyyaml dep).

---

## 6. 2026-10-04 update — remaining Track A/B gaps closed in code

- SparkLend/Compound coverage is now first-class in the DeFiLlama lending
  path: multi-project filters plus canonical protocol labels. The committed
  yields snapshot contains 118 joinable SparkLend/Compound rows.
- Backstop reads remain Ethereum-only for verified Umbrella deployments;
  Base/Arbitrum/Optimism RPC endpoints are configured, but non-Ethereum
  sources require `verified_by` provenance and no unverified addresses are
  included.
- Optional Zhipu GLM provider added without changing default selection.
- Local HackerOne-style staged disclosure added; staging never submits.
- Release SBOM verification is now fail-closed in the release workflow.
