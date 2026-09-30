# 🔍 Deep-Dive Competitor Research — 2026-09-27

**Parent:** `01-COMPETITIVE-RESEARCH.md` (2026-09-24) · `05-FACT-CHECKS.md`
**Trigger:** "jo hum kar rahe hain wesa kisi ne kiya hi hoga — find out"
**Method:** live web research (products, governance forums, academic tools,
open-access literature) + artifact collection + security audit (`artifacts/security-audit.py`)

---

## 0. Verdict (5 lines)

1. **Exact hamara product — "token fail → blast radius score, deploy se pehle"
   — abhi bhi koi nahi bechta.** 2026-09-24 wali conclusion live-verified.
2. **Sabse kareeb khiladi: `LlamaRisk`** — Aave/Ethena/Curve ke liye *manual*
   token-listing risk reviews + governance posts (hamara P1.3 template jo
   hai, wo log **haath se** likh ke bech rahe hain). Inka `LlamaGuard` +
   **PT Risk Oracle (Sep 2026, Aave pe live)** on-chain risk params productize
   kar raha hai.
3. **Dusra kareeb: BA Labs (Block Analitica)** — 2019 se MakerDAO/Sky risk
   team, governance-funded service model. LlamaRisk jaisa hi — manual advisory.
4. **Academic side mein math already mojood hai** (network fragility, TVL
   cascade, price-manipulation detection) lekin **koi product nahi bana** —
   aur kuch tools (DeFort, DeFiPoser, CPMMX) sirf research artifacts hain.
   "Publish or perish" risk real hai: 1-2 groups productize kar sakte hain.
5. **Hamara differentiation ab bhi sahi hai** — lekin P1.3 ko "template" nahi,
   **LlamaRisk ke manual review ka automation** ke roop mein position karo.

---

## 1. Naye competitors / players (existing list mein NAHI the)

### 🥊 Direct-ish — listing/risk analysis, pre-deploy

| Player | Kya karta hai specifically | Model | Kyun important |
|---|---|---|---|
| **LlamaRisk** (llamarisk.com) | Token onboarding risk reviews for **Aave governance** (AIP posts with risk assessment), collateral analysis, liquidity buffer reviews, `LlamaGuard`, **PT Risk Oracle** (on-chain, live Sep 2026) | Governance-funded service provider (Aave, Ethena, Curve) | **Hamara #1 reference competitor.** Hamara P1.3 unka daily deliverable hai. Manual → hamara automation angle |
| **BA Labs / Block Analitica** (x.com/BlockAnalitica) | Risk team behind **Sky (MakerDAO) USDS/DAI** since 2019; risk assessments, parameter proposals | Service provider (DAO-funded) | Same model as LlamaRisk; India/EU-friendly remote team precedent |
| **Chaos Labs "Risk Oracle" / Gauntlet "Aera"** | On-chain risk parameter automation (already in list — lekin **on-chain oracle trend** naya note hai) | SaaS + on-chain | Risk params → on-chain ja raha hai; hamara score bhi eventually oracle ban sakta hai |

### 🔍 Adjacent — audit/monitoring hybrids (naya detail)

| Player | Specifics (verified 2026-09-27) | Gap vs us |
|---|---|---|
| **Dedaub** | 300+ audits, **$70B protected**; **Security Suite** = contract inspection + vuln discovery + **transaction structuring** + monitoring API (Watchdog; Fantom integration) | Code-level; no contagion/impact-radius scoring |
| **Cantina / Spearbit** | Audit competitions + curated researcher network (list mein thin coverage) | Same — code review, not blast radius |

### 🎓 Academic tools & papers (2020–2026) — proof ki math exist karti hai

| Tool / Paper | Kya karta hai | Hum kya seekh sakte hain |
|---|---|---|
| **DeFort** (2024) | Automatic detection + analysis of **price manipulation attacks** in DeFi | Economic-attack classes > regex reentrancy. Hamare scanner mein ye classes chahiye |
| **DeFiPoser** (CCS 2021) | Symbolic execution se **economic exploit synthesis** | "Attack bana ke dikhana" = hamara sandbox-PoC angle, academic precedent |
| **DeFiTainter / DeFiRanger** | Taint/tx-graph se attack tracing (post-hoc) | Retrospective — hamara prospective angle valid |
| **CPMMX** | Automated attack synthesis for CPMMs | Niche; AMM-specific |
| **HOUSTON** | Real-time anomaly detection (NDSS-class) | Runtime ring — avoid |
| **TxRay** (arXiv 2602.01317) | Post-mortem + executable PoC (already known; PDF re-downloaded) | Hamara "prove" step competitor |
| **arXiv 2601.08540** (Jan 2026) | **"Systemic Risk in DeFi: Network-Based Fragility Analysis of TVL"** | ⚠️ Ye hamara **math model** hai literature mein — cite + benchmark karo (paper P4.3) |
| **arXiv 2508.12007** (Aug 2025) | Mapping Microscopic & Systemic Risks in TradFi+DeFi | Contagion taxonomy — hamara graph design validate karta hai |
| **arXiv 2411.01230** | Static analysis for flash-loan vulnerabilities | Scanner improvement seed |
| **ACM 2026 (3817054)** | Event-enriched **price oracle manipulation** detection (pre-exploit code analysis trend) | Oracle-config checks = hamara config auditor, unka detection. Complementary |
| **ISSTA25 execution property graphs** | Pre-deployment smart-contract analysis w/ property graphs | Graph-based pre-deploy analysis = methodological kin |
| **BlockLM** (Berkeley EECS-2026-241) | LLM + graphs se "proactively detect and prevent" | LLM angle — hamara provider-registry advantage |

### 📚 Institutional reports (analysis, not products)

- **NY Fed EPR 2024** — "Financial Stability Implications of Digital Assets" (downloaded)
- **BIS Quarterly 2021** — "DeFi risks and the decentralisation illusion" (bot-wall; link-only)
- **CRS R48883 (2026)** — "An Overview of DeFi" (bot-wall; link-only)
- **ESRB NBFI Monitor 2025**, **FATF DeFi report (Jul 2026)** — regulatory context

---

## 2. Overlap matrix — kaun hamare exact claim ke kitna kareeb hai

| Claim | LlamaRisk | BA Labs | Gauntlet/Chaos | Dedaub | TxRay | Academic (2601.08540) | **Hum** |
|---|---|---|---|---|---|---|---|
| Pre-deploy risk answer | ✅ manual | ✅ manual | ✅ params only | ❌ | ❌ (post-hoc) | ✅ method | ✅ **automated** |
| Contagion/blast-radius score | ⚠️ narrative | ⚠️ narrative | ❌ | ❌ | ⚠️ incident-scoped | ✅ math | ✅ **product** |
| Bad-debt simulation | ✅ scenarios | ✅ scenarios | ✅ param-level | ❌ | ❌ | ✅ | ✅ |
| Config audit (DVN/oracle) | ⚠️ ad-hoc | ⚠️ ad-hoc | ❌ | partial | ❌ | ❌ | ✅ |
| Public free calculator | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ (P1.2 done) |
| Governance deliverable | **✅ unka core** | ✅ | ⚠️ | ❌ | ❌ | ❌ | ✅ template → automate |

**Sabse bada learning:** market mein "risk review" ka **demand proven** hai
(LlamaRisk/BA Labs governance seats bech rahe hain) — lekin delivery **manual
consultancy** hai. Hamara pitch: *"LlamaRisk ka deliverable, ghanton mein nahi
— seconds mein, reproducible."* Wo hamare channel/competitor dono hain.

---

## 3. Kya implement / improve karein — aspect-wise

### A. Scanner layer (code analysis)
1. **Solidity/DeFi-native vuln classes** (blind test mein 0/4 pakde):
   reentrancy, tx.origin auth, unchecked low-level calls, delegatecall,
   weak randomness, allowance/approval bugs.
2. **Economic attack patterns** (DeFort/DeFiPoser se seekho): price oracle
   manipulation, flash-loan-assisted patterns, governance attack surfaces.
3. **Confidence recalibration** — pickle-class sinks 0.5 pe daba hua hai
   (default cutoff 0.7); taint-weak sinks ka alag tier chahiye.

### B. Data layer (asli moat)
4. **P2.1 live ingestion** (DeFiLlama + subgraphs + on-chain reads) — LlamaRisk
   ka moat hai *governance trust + manually maintained data*; automation hi
   hamara counter hai. Seed snapshot → live graph = priority #1.
5. **Exploit corpus (P2.3)** ke liye `DeFiHackLabs`, `ChainSec`, rekt.news —
   har download pe `artifacts/security-audit.py` chalao (corpus = untrusted files).

### C. Product surface (LlamaRisk ko automate karo)
6. **P3.2 PDF report** = unke AIP-review ka machine version. Template se aage
   badho: "one command → governance-ready listing review".
7. **P1.3 ko live karo** — Aave forum pe ek real retro post (rsETH wala
   example ready hai). LlamaRisk ke recent onboarding reviews padh ke structure
   match karo (unke governance posts = free spec).
8. **Risk Oracle watch** — LlamaGuard/PT Risk Oracle on-chain ja raha hai;
   hamara `blast_radius_score` bhi oracle-able hai (long-term, P5 ke saath).

### D. Research credibility (inbound leads ka engine)
9. **arXiv 2601.08540 se benchmark** karo — hamara hop-decay model vs unka
   network-fragility method. Paper (P4.3) ka related-work section yahin se banta hai.
10. DeFort/DeFiPoser/CPMMX citations = hamara "first product, not first paper"
    positioning.

### E. Business model
11. LlamaRisk/BA Labs = **acqui-hire/partner candidates** (governance seats +
    hamara automation). Sherlock partnership (P4.1) ke saath-saath inhe bhi
    approach list mein daalo.

---

## 4. Artifact inventory (2026-09-27 wave)

**Downloaded + security-audited (13 files, SHA256SUMS generated, 0 hard fails):**

| File | Source | Note |
|---|---|---|
| `papers/mapping-microscopic-systemic-risks-tradfi-defi.pdf` | arXiv 2508.12007 | Contagion taxonomy |
| `papers/systemic-risk-defi-network-tvl-fragility.pdf` | arXiv 2601.08540 | ⭐ Hamare math ka benchmark |
| `papers/flashloan-vulns-static-analysis.pdf` | arXiv 2411.01230 | Scanner seeds |
| `papers/txray-agentic-postmortem.pdf` | arXiv 2602.01317 | Prove-step rival |
| `papers/smart-contract-execution-property-graphs-issta25.pdf` | ISSTA25 | Method kin |
| `papers/defi-ecosystems-review-mdpi2024.pdf` | MDPI (open access) | Survey |
| `reports/nyfed-financial-stability-digital-assets-2024.pdf` | NY Fed | Institutional |
| `reports/defi-critical-infrastructure-security-area-2024.pdf` | U. Oregon AREA | DeFi infra security |
| *(Easley & Kleinberg textbook — not vendored; official free edition at cs.cornell.edu/home/kleinber/networks-book/)* | Cornell | Network/contagion textbook |
| `blogs/blockaid-kelpdao-dvn-292m.html` | blockaid.io | Founding case source |
| `blogs/chainalysis-kelpdao-bridge-exploit.html` | chainalysis.com | Attribution source |
| `blogs/layerzero-kelpdao-incident-report.html` | layerzero.network | Primary source |
| `blogs/openzeppelin-lessons-from-kelpdao.html` | openzeppelin.com | Post-mortem lessons |
| `security-audit.py` + `SHA256SUMS` | this repo | Reusable download audit |

**Security audit result:** PDFs sab clean (`/OpenAction` = `/S /GoTo`
navigation only; **zero** /JavaScript, /Launch, /EmbeddedFile). HTML pages
mein `<script>` tags normal (blog CDNs; offline inert). Hunter scanner:
0 findings. Executables: none.

**Manual grab list (bot-walls/paywalls — officially free hai, browser se lo):**

| Item | URL | Kyun chahiye |
|---|---|---|
| BIS — DeFi risks & decentralisation illusion | bis.org/publ/qtrpdf/r_qt2112b.pdf | Regulatory framing |
| CRS R48883 — Overview of DeFi | crsreports.congress.gov/product/pdf/R/R48883 | Public-domain US report |
| **Token Economy 3rd ed (Voshmgir)** | zenodo.org/records/15358988 (DOI 10.5281/zenodo.15358988) / web: token.kitchen | **Book** — open access, Zenodo IP-blocked here |
| How to DeFi (CoinGecko) | coingecko.com/en/candy/rewards/how-to-defi-beginner | Book — account-gated distribution (no pirated mirrors used) |
| Contagion in Decentralized Lending (Compound V2) | dl.acm.org/doi/10.1145/3605768.3623544 | ⭐ Math core (paywall — author copy dhundo) |
| CPMMX | dl.acm.org/doi/10.1145/3728872 | Attack synthesis (paywall) |
