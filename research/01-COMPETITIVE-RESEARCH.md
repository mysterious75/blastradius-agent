# 🔴 BlastRadius — Competitive & Market Research Dossier

**Date:** 2026-09-24
**Scope:** DeFi composability/contagion risk, exploit blast-radius analysis, Web3 smart-contract security SaaS
**Sources covered:** general web, GitHub, Hugging Face, arXiv/ACM/academic, Reddit/Twitter signals, M&A databases
**Artifacts collected:** `research/artifacts/` (see `artifacts/INDEX.md`)

> ⚠️ **Scope note:** This is *market & product* research only. Nothing here is offensive tooling guidance — attack techniques are referenced only at the level needed to map the competitive landscape.

---

## 0. 🎯 Verdict in 5 lines

1. **"Blast radius / contagion" as a *product* — kisi ke paas nahi hai.** Log ispe *blog likhte hain* (Blockaid), *papers likhte hain* (academia), aur *parameters tune karte hain* (Gauntlet/Chaos Labs). Koi **prospective, pre-deployment "blast radius score"** nahi bechta. ← **tumhara white space.**
2. **Market real hai aur tezi se consolidate ho raha hai** — 2019–2026 mein **kam se kam 9 acquisitions + 3 IPO filings**. Exit path exists.
3. **Lekin valuations patle hain** — median exit ~$50M. Outlier: **CertiK IPO at $2B** (Jan 2026).
4. **Tumhara closest technical rival `TxRay` (arXiv, Jan 2026)** hai — wo bhi "agentic exploit analysis + executable PoC" karta hai. **Lekin wo *retrospective* hai (hack ke baad), tumhe *prospective* (hack se pehle) hona chahiye.**
5. **Sabse bada risk: "tool-only" products marte hain.** MythX ko acquire karke **sunset** kar diya gaya. Data + service moat banao.

---

## 1. 🗺️ Market Map — 5 Rings

```
                    ┌─────────────────────────────────────┐
   RING 1 (EMPTY)   │  BLAST RADIUS / CONTAGION SCORING   │  ← TUM YAHAN HO
                    │  (koi product nahi, sirf blogs+paper)│
                    └─────────────────────────────────────┘
   RING 2  Runtime / on-chain threat detection
           Chainalysis-Hexagate · Hypernative · Blockaid · Forta · Decurity Defimon
   RING 3  Economic risk & simulation
           Gauntlet · Chaos Labs · Exponential · L2Beat · DeFiSafety · Certora
   RING 4  Audit firms & contest platforms
           Trail of Bits · OpenZeppelin · Cyfrin · Sherlock · Zellic · Code4rena
           Halborn · Quantstamp · Spearbit · Nethermind · QuillAudits · Beosin · BlockSec
   RING 5  Automated scanners / SAST-DAST / LLM audit
           Slither · Mythril · Echidna · Ityfuzz · DeFiTainter · CPMMX · TxRay
           SolidityScan (CredShields) · LLMBugScanner · SmartLLM · Solidity-LLM
```

---

## 2. 🏢 Company Profiles (country · owner · funding · valuation · technique)

### RING 1 — Jo tumhare closest hain (lekin koi direct competitor nahi)

| Company | Country | Owner / Founder | Funding | Valuation | Technique |
|---|---|---|---|---|---|
| **Blockaid** | 🇮🇱 Israel (Tel Aviv) | **Ido Ben-Natan** (CEO, co-founder, ex-military cyber) | **$33M** ($6M seed + $27M Series A, Oct 2023) | undisclosed | Transaction simulation, wallet/dApp protection, **real-time detection**. Blog mein literally *"DeFi Contagion: The Composability Cascade"* section likha hai |
| **Hypernative** | 🇮🇱 Israel | **Gal Sagie** | **$16M Series A** (Sep 2024) | undisclosed | Real-time threat detection — "biggest player in the field" (Decurity) |
| **Hexagate** | 🇮🇱 Israel | — | raised **$8.6M** total | **ACQUIRED by Chainalysis** (18 Dec 2024) at **~$60M** unofficial | ML-based web3 threat detection |
| **Forta** | 🇺🇸 US | (OpenZeppelin spin-out lineage) | ~$31M+ | n/a | Decentralized bot network for on-chain monitoring |

### RING 3 — Economic risk / simulation (tumhara second-order competitor)

| Company | Country | Technique | Notes |
|---|---|---|---|
| **Gauntlet** | 🇺🇸 US (NYC) | Agent-based economic modeling, market risk for DeFi | Aave/Compound risk vendor; param tuning, **exploit contagion nahi** |
| **Chaos Labs** | 🇺🇸/🇮🇱 | **Risk & Simulation Platform**, agent-based modeling, fork simulation | Aave governance ka official vendor ([proposal](https://governance.aave.com/t/updated-proposal-chaos-labs-risk-simulation-platform/10025)) |
| **Exponential** | 🇺🇸 US | DeFi pool risk ratings (letter grades) | Investor-facing risk rating |
| **L2Beat** | 🇪🇺 EU | L2 risk framework (Stage 0/1/2) | Community/public good + grants |
| **DeFiSafety** | 🇨🇦 CA | Process/safety ratings for protocols | Process score, not exploit modeling |
| **Certora** | 🇮🇱/🇺🇸 | Formal verification (Certora Prover) | Specification-based proofs |

### RING 4 — Audit firms (buyers/partners, not competitors)

| Firm | Country | Position |
|---|---|---|
| **Trail of Bits** | 🇺🇸 US | "Gold standard", crypto R&D (Slither, Echidna author) |
| **OpenZeppelin** | 🇺🇸 US | Institutional credibility. ⚠️ **S&P Global M&A alert Sep 2026** — lagta hai acquisition chal raha hai |
| **Cyfrin** | 🇺🇸/🇬🇧 | EVM private-audit depth + ecosystem tooling (Cyfrin Rekt, Solodit) |
| **Sherlock** | 🇺🇸 US | Audit + **financial coverage/warranty** (unique) |
| **Zellic** | 🇺🇸 US | Acquired **Code4rena** (Aug 2024) → launched **Zenith** |
| **CertiK** | 🇺🇸/🇨🇳 | Mass-market, SEO-heavy. **IPO Jan 2026 @ $2B**. Reputation controversial |
| **Halborn · Quantstamp · Spearbit · Nethermind · QuillAudits · Beosin · BlockSec · Hacken · Decurity** | mixed | Established players |

---

## 3. 💰 M&A + IPO Tracker — ASLI VALUATION DATA

> Source: **Decurity — "Web3 Security M&As and IPOs"** (11 Feb 2026) — `decurity.io/research/web3-security-m-and-a-and-ipos`
> Full extract: `artifacts/key-extracts-valuation-and-MA.md`

### Acquisitions

| Date | Target | Acquirer | Valuation | Notes |
|---|---|---|---|---|
| Nov 2019 | **MythX** (Mythril) | Consensys Diligence | ~$0 | ⚠️ **baad mein SUNSET** — tool-only product mar gaya |
| Jan 2020 | **Chainsecurity** | PwC (Switzerland) | ~$0 | Baad mein wapas spin-out |
| Jul 2024 | **Wallet Guard** | Consensys (MetaMask) | **~$40M** (unofficial) | Wallet anti-fraud |
| Aug 2024 | **Code4rena** | **Zellic** | **~$1M** 😬 | Distressed — cash khatam, liquidity crisis. Zenith bana |
| Nov 2024 | **Blowfish** | **Phantom** | **~$55M** (unofficial) | Paradigm ne $11.8M lagaya tha 2022 mein. Founders ko ~$2–6M net cash |
| Dec 2024 | **Hexagate** | **Chainalysis** | **~$60M** (unofficial) | Sirf $8.6M raise kiya tha. Founders ko ~$3.5–9M each |
| Jan 2025 | **Fuzzland** (ityFuzz) | **Solayer** | n/a | $3M seed (2024) ke <1 saal mein acqui-hire. Team+tech, business nahi |
| Jan 2025 | **Alterya** | **Chainalysis** | **$150M** ✅ | Anti-fraud. $9.8M raise tha (2022). **Sabse successful exit** |
| Feb 2025 | **Cyberscope** (60% stake) | **TAC Infosec** 🇮🇳 (public) | **$2.3M** | 98% margins, $1.4M revenue — "rubber-stamp token audits" |

### IPOs

| Date | Company | Planned Valuation | Notes |
|---|---|---|---|
| Aug 2025 | **Hacken** (→ HAI Group) | n/a | Abu Dhabi listing planned. 2023 token sale ne **$23.9M** pe value kiya |
| Dec 2025 | **Cyberscope** | **$119M** 🤨 | NASDAQ. **52x** of 10-month-old acquisition price. Decurity ne "financial engineering" bola |
| **Jan 2026** | **CertiK** | **$2B** 🔥 | Same as 2022 round. Pehla "real" web3 cybersecurity listing. Reputation: at least **9 audited projects hack hue** (rekt.news) |

### 📌 Kya seekhna hai
- **Exit ka rasta hai** — Chainalysis (2 deals), Phantom, Consensys (2), Zellic, Solayer, PwC, TAC sab khareed rahe hain.
- **Lekin price patla hai** — median ~$50M. $100M+ sirf **Alterya** ne maara (anti-fraud, high recurring).
- **Anti-fraud / runtime monitoring** sabse zyada value commands karta hai. Static audit sabse kam.
- **Service + data > tool.** MythX = tool-only = sunset. Sherlock = audit + warranty = alive.
- **India angle:** TAC Infosec (listed, 🇮🇳) already iss space mein acquire kar raha hai. Exit ke liye ek plausible buyer.

---

## 4. 🔬 Technique & Process — Academic + Open Source

### 4.1 Contagion / Blast-radius modelling (tumhara CORE technique)

| Work | Venue / Year | Kya karta hai | Tumhare liye |
|---|---|---|---|
| **"The Decentralized Financial Crisis: Attacking DeFi"** — Gudgeon et al. | 2020 | 🏛️ **Foundational paper.** Dikhaya ki collateralized debt composition se ek protocol ka failure cascading crisis ban sakta hai | Origin story. Cite karo |
| **"Contagion in Decentralized Lending Protocols: A Case Study of Compound V2"** | ACM FC 2024 — `10.1145/3605768.3623544` | 🧮 **Balance-sheet network construct** karke financial contagion model kiya | **YE TUMHARA MATHEMATICAL CORE HAI.** Isko product banao |
| **"Decentralized finance security: A survey of attacks, defenses…"** | ScienceDirect 2026 — `S2667295226000024` | Survey; explicitly *"systemic economic contagion"* ko risk category maanta hai | Literature review |
| **"Mythos-Class AI and Blockchain Systemic Risk"** | Preprints `202605.0128` (May 2026) | 🎯 **"blast radius" ko literally ek *rated quantity* define karta hai** | Sabse naam-se closest paper. Padho |
| **"Stablecoins: financial risks, vulnerabilities…"** | Frontiers in Blockchain 2026 | Systemic risk lens | Adjacent |
| **"DeTEcT — Decentralized token economy theory"** | Frontiers 2023 | Agent-based dynamical simulation of token economies | Method reference |

### 4.2 Exploit detection / attack synthesis (tumhara engine layer)

| Work / Tool | Venue | Kya karta hai | Threat level |
|---|---|---|---|
| **TxRay: Agentic Postmortem of Live Blockchain Attacks** | arXiv `2602.01317` (Jan 2026) — 📥 **downloaded** | 114 DeFiHackLabs incidents pe: expert-aligned **root-cause report + executable PoC** (105/114) | 🔴🔴🔴 **Sabse bada rival.** Tumhare "prove" step jaisa. **PDF liya** |
| **CPMMX: Automated Attack Synthesis for CPMMs** | ACM `10.1145/3728872` | AMM ke liye **automated attack synthesis**. Baselines: Echidna, Ityfuzz, DeFiTainter, Slither, Mythril | 🔴🔴 Economic attack synthesis |
| **DeFiTainter** | (CPMMX baseline) | Taint/data-flow analysis for DeFi exploits | 🔴 |
| **Ityfuzz** (Fuzzland → Solayer) | Open source | Property-guided + input-guided fuzzing of contracts | 🔴 Acquired |
| **HOUSTON: Real-Time Anomaly Detection of Attacks against Ethereum DeFi Protocols** | NDSS / UCSB | Real-time on-chain attack anomaly detection | 🔴🔴 Runtime layer |
| **"Smart Contract and DeFi Security Tools: Do They Meet the Needs of Practitioners?"** | ACM ICSE 2024 — `10.1145/3597503.3623302` | Practitioner study. **$6.45B** cumulative losses cited | Market sizing ammo |
| **"Demystifying Invariant Effectiveness for Securing Smart Contracts"** | ACM `10.1145/3660786` | Attack txns ka behaviour benign se alag hota hai — invariant detection | Method |
| **Slither** (Trail of Bits) | OSS | Solidity static analysis | Commodity |
| **Mythril** (ConsenSys) | OSS | Symbolic execution | Commodity |
| **Echidna** (Trail of Bits) | OSS | Property-based fuzzing | Commodity |
| **Foundry invariant tests** | OSS | Modern auditor toolchain | Commodity |

### 4.3 LLM / AI audit layer

| Work | Source | Kya |
|---|---|---|
| **LLMBugScanner** | arXiv `2512.02069` (Nov 2025) — 📥 **downloaded** | LLM + fine-tuning se smart-contract vuln detection |
| **"Combining Fine-tuning and LLM-based Agents for Intuitive Smart Contract Auditing"** | arXiv `2403.16073` — 📥 **downloaded** | **1,734 vulnerable functions from 263 real audits** dataset banaya (agentic + fine-tuned hybrid) |
| **SmartLLM** | HF Papers `2502.13167` | Custom GenAI for auditing |
| **EVuLLM** | MDPI Electronics 14(16) 2025 | **Dataset** for ETH smart-contract vuln detection |
| **TxRay** (again) | arXiv | Agentic postmortem — LLM-based |

---

## 5. 🤗 Hugging Face — Models & Datasets

| Asset | Type | Details | Use for BlastRadius |
|---|---|---|---|
| **[Chain-GPT/Solidity-LLM](https://huggingface.co/Chain-GPT/Solidity-LLM)** | Model | **2.78B params**, finetune of `Salesforce/codegen-2B-multi`, MIT, **1.58k likes / 4.2k downloads**, 2-stage (pretrain Solidity corpus → instruction finetune) | Baseline ya distillation source |
| **[credshields/Solidity-CodeGen-v0.1](https://huggingface.co/credshields/Solidity-CodeGen-v0.1)** | Model | Solidity codegen with OpenZeppelin patterns (CredShields = **SolidityScan** company) | Competitor ka model — benchmark karo |
| **[WhitzardAgent/CyberSecurity-1M](https://huggingface.co/datasets/WhitzardAgent/CyberSecurity-1M)** | Dataset (Jun 2026) | 1M cybersecurity corpus incl. **Web3/smart-contract security**, AI vuln scanning | Pretraining corpus |
| **EVuLLM dataset** | Dataset | Labeled ETH contract vulnerabilities | Eval set |
| **arXiv 2403.16073 dataset** | Dataset | 1,734 vulnerable functions + reasons, from 263 audits | **Sabse valuable labelled set** |
| **SmartBugs / SmartBugs-Wild** | Dataset | Canonical vuln corpus | Baseline eval |

---

## 6. 📦 Datasets — Training / Eval ke liye gold

| Source | Size | Link | Notes |
|---|---|---|---|
| **ChainSec — Documented Timeline of DeFi Exploits** | **191 exploits, $6,116,823,000** losses (to 2026-04-30) | `chainsec.io/defi-hacks` | 🥇 **Sabse structured exploit timeline.** Har entry mein date, protocol, amount, root cause, source link |
| **DeFiHackLabs** (SunWeb3Sec) | 100+ Foundry PoCs | `github.com/SunWeb3Sec/DeFiHackLabs` | 🥇 **Reproduced exploits** = labelled attack data. TxRay ne isi pe train kiya |
| **DeFiVulnLabs** (SunWeb3Sec) | vuln patterns | `github.com/SunWeb3Sec/DeFiVulnLabs` | Synthetic vuln patterns |
| **DeFiLlama Hacks DB** | large | `defillama.com/hacks` | Loss amounts |
| **rekt.news Leaderboard** | curated | `rekt.news/leaderboard` | Investigative post-mortems (incl. CertiK-audited failures) |
| **NVD + GitHub Advisory DB** | 300+ web3 advisories | — | tumhare `prometheus` mein already hai |

---

## 7. 📡 Community & Intelligence Signals (Reddit / Twitter / Blogs)

### Post-mortem / incident feeds (ye padhte hain serious log)
| Source | Type | Khaas baat |
|---|---|---|
| **rekt.news** | 📰 Investigative journalism | Long-form post-mortems. Leaderboard = shame list |
| **BlockSec** | 🏢 Vendor blog | Weekly incident roundups |
| **PeckShield** (`@PeckShieldAlert`) | 🏢 Twitter alerts | Sabse fast alerts |
| **SlowMist** (`@SlowMist_Team`) | 🏢 | AML + threat intel |
| **Cyvers** | 🏢 | Real-time alerts |
| **Defimon Alerts** (`@DefimonAlerts`) | 🏢 = **Decurity** ka monitoring product | On-chain alerts |
| **NOMINIS** | 📊 Monthly reports | Country: UAE/RU-adjacent |
| **Three Sigma** | 📝 Blog breakdowns | Clean exploit writeups |
| **SmartContractShacking** | 📝 | Incident writeups |
| **Immunefi** (Medium) | 🏢 | Bounty platform, publishes loss reports |
| **SolidityScan / Beosin / QuillAudits / CertiK blogs** | 🏢 | SEO content, some good research |
| **mouse-run** (beehiiv) | 📰 | Niche newsletter |
| **SEAL** (Security Alliance) | 🤝 Incident response collective | KelpDAO case mein involved the |

### Reddit / community toolchain consensus (2026)
- Modern auditor stack = **manual review + Foundry invariant tests + Slither + Mythril + Echidna** (`web3.career`)
- Practitioners repeatedly complain automated tools ke **false positives** — yahi tumhara opening hai
- **AI agent "skills"** ka trend chalu hai — `gmh5225/awesome-web3-security` ne `npx skills add` se web3 security skills publish kiye (`smart-contract-security`, `solana-security`, `mev-security`, `wallet-security`, `web3-security-tooling`)

---

## 8. 🏗️ GitHub Repositories — Tu kitna already khada hai

| Repo | Kya hai | Tumse overlap |
|---|---|---|
| **`SunWeb3Sec/DeFiHackLabs`** | Foundry PoC reproductions of real DeFi hacks | ⚠️ Data source — **use karo, compete mat karo** |
| **`gmh5225/awesome-web3-security`** | Massive curated list + AI-agent skills | Lead magnet reference |
| **`Quillhash/Web3-Security-Tools`** | Tool aggregator | Reference |
| **`nirholas/lyra-intel`** | "AI-Powered Code Review", audited-contracts DB | 🔴 Mild competitor |
| **`blockthreat/blocksec-ctfs`** | CTF archive | Training data |
| **`crytic/*`** (Trail of Bits) | Slither, Echidna | Commodity deps |
| **`Decurity/*`** | Open data + Defimon | Reference |

> **Tumhare `blastradius-agent` + `prometheus`** already in sabse zyada karte hain (scan → prove → patch → verify + 41-55 scanners + disclosure pipeline). **Jo missing hai wo dekho §10.**

---

## 9. 📥 Artifacts Downloaded (`research/artifacts/`)

| File | Size | Source |
|---|---|---|
| `txray-agentic-postmortem-live-blockchain-attacks.pdf` | 845 KB | arXiv 2602.01317 |
| `llmbugscanner-smart-contract-auditing.pdf` | 1.1 MB | arXiv 2512.02069 |
| `auditing-agents-finetuning-smart-contracts.pdf` | 1.5 MB | arXiv 2403.16073 |
| `iota-101-blockchain-usecases-handbook.pdf` | 17 MB | IOTA Foundation 2025 (Chainalysis acquisitions ka reference) |
| `key-extracts-valuation-and-MA.md` | — | M&A valuations + KelpDAO case notes |
| `INDEX.md` | — | Inventory + manual-download list |

**Jo automatically nahi mil paye (paywall / bot-wall) — manual grab list `artifacts/INDEX.md` mein hai.**

---

## 10. 🎯 GAP ANALYSIS — BlastRadius kahan jeet-ta hai / kahan haarta hai

### ✅ Jeet ka white space (koi nahi bech raha)
1. **Prospective "blast radius score"** — deployment se pehle batao: *"agar ye contract hack hua to kitna TVL, kitne protocols, kaunse L2s affected?"*
   - Blockaid **blog** likhta hai (KelpDAO case) — product nahi
   - Gauntlet/Chaos **parameter tuning** karte hain — exploit contagion nahi
   - Academia **papers** likhta hai — product koi nahi banaya
2. **Collateral-whitelisting risk API** — lending protocols (Aave, Compound, SparkLend, Fluid) ko bolo: *"rsETH jaise LRT ko collateral maanna = ye contagion exposure"*. **KelpDAO ne Apr 2026 mein exactly ye prove kiya.**
3. **Cross-chain verification-config auditor** — LayerZero DVN, bridge security configs ka static audit. KelpDAO = **1-of-1 DVN config** tha. Koi tool ye systematically check nahi karta (Blockaid ne ek bash gist diya — kaafi nahi).

### ⚠️ Haar ka risk (jo already kisi ne kar rakha hai)
| Risk | Kaun | Tumhara counter |
|---|---|---|
| **"Agentic exploit analysis + PoC"** | **TxRay** (research) | Wo *retrospective*. Tum *prospective* + **patch + verify** karo (TxRay patch nahi karta) |
| **Real-time on-chain monitoring** | Hexagate (Chainalysis), Hypernative, Forta | Ye **Ring 2** hai — yahan mat jao abhi. V1 = pre-deployment |
| **Economic simulation** | Gauntlet, Chaos Labs | Wo param tuning. Tum **exploit-driven contagion** — alag question |
| **LLM Solidity analysis** | ChainGPT, CredShields, LLMBugScanner, SmartLLM | Commodity fast. **Tumhara moat data hai, model nahi** |
| **Audit firms ke paas distribution** | ToB, OZ, Cyfrin, Sherlock | Unko **feeder bano** (pre-audit), competitor nahi |

### 🔴 Sabse bada structural risk
> **MythX (Mythril) ko acquire karke SUNSET kar diya gaya.** Fuzzland ko acqui-hire kiya (business chhod diya). Code4rena $1M pe bik gaya.
> **Lesson: tool-only products ki koi defensibility nahi.**

**Isliye moat banao:**
1. **DeFi Dependency Graph** 🏆 — *"kaunsa protocol kaunse token ko collateral maanta hai, kaunse bridge pe depend karta hai, kaunse oracle use karta hai."* Ye **data asset** hai. Ye koi nahi bechta. Ise continuous update karo.
2. **Exploit post-mortem corpus** — ChainSec (191) + DeFiHackLabs (100+) + rekt.news ko labelled dataset banao.
3. **Service layer** — warranty/coverage model (Sherlock jaisa) ya managed monitoring retainers.

---

## 11. 🧭 Recommended Positioning

> ### **BlastRadius — Pre-deployment contagion risk for DeFi**
> *"Ek contract ka exploit kitna TVL le doobe? Hum deploy se pehle batate hain."*

**Pehla buyer:** Lending/Aave-fork protocols ki **risk & governance** teams (collateral whitelisting), phir **insurers** (Nexus Mutual, InsurAce), phir **L2 / bridge** risk teams.

**Founding case study (free marketing):** KelpDAO / LayerZero DVN — $292M, 18 Apr 2026.
Ek DVN config (1-of-1) → $292M drain → **Aave V3/V4 WETH reserve pe unliquidatable bad debt** → SparkLend, Fluid, Upshift freeze → 20+ L2s pe wrapped rsETH worthless.
> Ye *literally* blast radius hai. Tumhare product ka naam hi case study hai. 🎯

**Moat:** DeFi Dependency Graph (§10).
**GTM:** free public "blast radius calculator" (paste a token address → contagion map) → leads.

---

## 12. 🔗 Master Source List

**Valuation / M&A**
- Decurity — *Web3 Security M&As and IPOs* (11 Feb 2026): `decurity.io/research/web3-security-m-and-a-and-ipos`
- Decurity — *Current state of web3 security products*: `decurity.io/research/current-state-of-web3-security-products`
- Architect Partners — *OpenZeppelin / S&P Global M&A Alert* (Sep 2026)
- The Block — CertiK IPO $2B · Blockaid $33M · Zellic/Code4rena
- Renaissance Capital — Cyberscope IPO $19M raise / $119M val
- IsraelVC FIRGUN — Israeli fundraisings (Hypernative $16M)

**Case study**
- Blockaid — *How a Single LayerZero DVN Compromise Drained $292M from KelpDAO*: `blockaid.io/blog/how-a-single-layerzero-dvn-compromise-drained-292m-from-kelpdao`
- ChainSec timeline: `chainsec.io/defi-hacks`
- rekt.news · DefiLlama Hacks

**Academic** — see §4 (all DOIs/arXiv IDs listed)

**Companies** — see §2

---

*Compiled 2026-09-24. Sab data public sources se; valuations "unofficial/rumored" jahan noted.*
