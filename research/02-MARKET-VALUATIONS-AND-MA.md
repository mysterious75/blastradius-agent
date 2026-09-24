# 💰 Key Extracts — Valuations, M&A & the KelpDAO Blast-Radius Case

> Sources: Decurity *"Web3 Security M&As and IPOs"* (11 Feb 2026) · The Block · Renaissance Capital · Chainalysis · Blockaid · ChainSec · IsraelVC FIRGUN
> **Ye summarised research notes hain (fair-use quoting), pura article copy nahi.**

---

## 1. 📊 M&A + IPO Valuation Table

| Date | Target | Acquirer | Valuation | Raise tha | Founder payout (est.) |
|---|---|---|---|---|---|
| 2019-11 | **MythX** (Mythril) | Consensys Diligence | ~$0 | OSS grant | — ⚠️ **baad mein sunset** |
| 2020-01 | **Chainsecurity** 🇨🇭 | PwC Switzerland | ~$0 | — | baad mein spin-out |
| 2024-07 | **Wallet Guard** | Consensys (MetaMask) | **~$40M** *(unofficial)* | small pre-seed | achha exit |
| 2024-08 | **Code4rena** | **Zellic** | **~$1M** 😬 | distressed | liquidity crisis |
| 2024-11 | **Blowfish** | **Phantom** | **~$55M** *(rumored, "quite low")* | **$11.8M** (Paradigm, 2022) | **$2–6M net upfront each** |
| 2024-12 | **Hexagate** 🇮🇱 | **Chainalysis** | **~$60M** *(rumored)* | **$8.6M** | **$3.5–9M each** after tax/liq-prefs |
| 2025-01 | **Fuzzland** (ityFuzz) | **Solayer** | n/a (low) | **$3M** seed (2024) | acqui-hire |
| 2025-01 | **Alterya** 🇮🇱 | **Chainalysis** | **$150M** ✅ | **$9.8M** (2022) | **sabse successful exit** |
| 2025-02 | **Cyberscope** (60%) | **TAC Infosec** 🇮🇳 (listed) | **$2.3M** | — | 98% margins / $1.4M rev |

| Date | Company | IPO valuation | Notes |
|---|---|---|---|
| 2025-08 | **Hacken** → HAI Group | n/a | Abu Dhabi. 2023 token sale = **$23.9M** val |
| 2025-12 | **Cyberscope** | **$119M** 🤨 | NASDAQ. **52x** 10-month-old acquisition price. Decurity: *"financial engineering"* |
| **2026-01** | **CertiK** | **$2B** 🔥 | = 2022 round price. Pehla "real" web3 cybersecurity listing |

### Kya pattern dikh raha hai
1. **Anti-fraud / runtime monitoring sabse zyada value commands karta hai** (Alterya $150M > Hexagate $60M > Blowfish $55M > WalletGuard $40M >>> Code4rena $1M).
2. **Static "rubber-stamp" audit sabse kam** (Cyberscope $2.3M).
3. **Contest platforms ki death** — Code4rena (pioneer) sirf $1M pe bik gaya.
4. **Raise multiple (exit/raised):** Alterya **15.3x** ✅ · Hexagate **7.0x** · Blowfish **4.7x** · Code4rena << 1x ❌
5. **Consolidators:** Chainalysis (×2) · Consensys (×2) · Phantom · Zellic · Solayer · PwC · TAC Infosec.
6. **⚠️ Tool-only = death.** MythX sunset. Fuzzland ka business chhoda. Sherlock (audit + warranty) alive.
7. **🇮🇳 India exit path real hai** — TAC Infosec (NSE-listed) already acquire kar chuka hai.

---

## 2. 🔴 KelpDAO / LayerZero DVN — The Perfect "Blast Radius" Case Study

> Source: **Blockaid** — *"How a Single LayerZero DVN Compromise Drained $292M from KelpDAO"* (19 Apr 2026)
> ⚠️ This is **defensive incident analysis of a public, already-happened event** — used here purely as a market/product case study.

### Ek line mein
**Ek misconfigured verifier (1-of-1 DVN) → $292M drain → Aave pe unliquidatable bad debt → 5+ protocols freeze → 20+ L2s pe token questionable.**

### Timeline
| Step | Kya hua |
|---|---|
| 0 | KelpDAO (EigenLayer LRT, **$1.07B TVL**, 2nd largest) — rsETH cross-chain ke liye LayerZero OFT |
| 1 | Attacker wallets **Tornado Cash** se pre-funded (planned, opportunistic nahi) |
| 2 | **Forged LayerZero packet** — Unichain se aane ka dawa, source tx **kabhi exist hi nahi kiya** |
| 3 | **1-of-1 DVN config** ki wajah se ek compromised signer set ne hi attestation de diya |
| 4 | Ethereum `OFTAdapter` ne (as-designed) **116,500 rsETH (~$292M)** release kar diye |
| 5 | Doosra attempt (40,000 rsETH, ~$100M) **KelpDAO ke emergency multisig ne 46 min mein pause** kar diya |
| 6 | Attacker ne **116,500 rsETH → Aave V3 collateral** daal ke WETH borrow kiya → **unliquidatable position** |
| 7 | 52,440 ETH consolidation address pe; USDC cross-chain bridge; ChangeNow/Binance se cash-out |

### 🌐 BLAST RADIUS MAP (ye hai tumhara product!)
```
                     ┌── LayerZero DVN (1 signer set compromised)
                     │
KelpDAO OFTAdapter ──┼── $292M rsETH drained
                     │
        ┌────────────┼────────────────────────────────────────┐
        ▼            ▼            ▼           ▼               ▼
   Aave V3/V4    SparkLend      Fluid    Upshift Finance   20+ L2s
   ─ rsETH       ─ rsETH        ─ rsETH  ─ paused          (Base, Arbitrum,
     frozen        frozen         frozen   (High Growth ETH,  Linea, Blast,
   ─ WETH pool   (precaution)             Kelp Gain)          Mantle, Scroll…)
     = BAD DEBT                                     
     (unliquidatable)                          wrapped rsETH on L2s
     Umbrella backstop                         = questionable backing
       needed to settle
```

### Root cause (asli failure)
**Koi contract bug NAHI tha.** `rsETH`, `OFTAdapter`, LayerZero ke on-chain contracts sab **as-designed** chale.
Failure thi **off-chain infrastructure + configuration** mein:
1. **1-of-1 DVN configuration** (structural — ek compromised signer = arbitrary message authorized)
2. DVN ke private signing keys / off-chain node pipeline ka compromise

### 🎯 Ye tumhare product ke 3 features seed karta hai
| Feature | Kya karega | KelpDAO mein value |
|---|---|---|
| **Config Auditor** | Cross-chain verification config scan: `requiredDVNCount < 2 && optionalDVNCount == 0` → 🔴 CRITICAL | **Pakad leta** — 1-of-1 config tha |
| **Contagion Mapper** | Token → collateral whitelist graph → downstream protocol/TVL exposure | **Aave/Spark/Fluid/Upshift + 20 L2s ka graph** dikhata |
| **Bad-Debt Simulator** | *"agar X token worthless ho jaye to kaunse lending pools insolvency jayenge"* | **Aave WETH reserve ka unliquidatable bad debt** predict ho jaata |

### 📣 GTM angle
Blockaid ne ye blog likha (acchi research, achha SEO). **Lekin unka product transaction-simulation hai — ye analysis sirf marketing tha.**
Tum bolo: *"Hum ye graph **deploy se pehle** dete hain. KelpDAO ko agar ek `blast-radius report` milta to 1-of-1 DVN config reject ho jaata."*

---

## 3. 📈 Market Sizing Anchors (public data)

| Metric | Value | Source |
|---|---|---|
| Cumulative smart-contract/DeFi losses | **$6.45B** | ACM ICSE 2024 practitioner study |
| Documented DeFi exploits (to Apr 2026) | **191 incidents / $6.12B** | ChainSec timeline |
| Q1 2026 crypto exploits | **$169M** (declining YoY) | Cointelegraph Q1 2026 report |
| Biggest 2026 single event | **KelpDAO $292M** (Apr 2026) | The Block |
| Audit deal sizes | $10k–$500k, 2–6 weeks | industry |
| Audit micro-SaaS pricing | **$29–199/mo** | rightleftagency 2026 roundup |
| Largest exit | **Alterya $150M** | Decurity |
| Highest valuation | **CertiK IPO $2B** | The Block, Jan 2026 |

---

## 4. 🧭 Is data se nikalta hua strategy

1. **Runtime monitoring (Ring 2) mein mat ghuso abhi.** Wahan Hexagate/Hypernative/Blockaid khade hain + Chainalysis jaisi company already khareed chuki hai.
2. **Static audit (Ring 4) commodity hai.** Margins ghat rahe hain, CertiK jaise log SEO se jeet rahe hain.
3. **White space = "pre-deployment contagion / blast radius scoring" (Ring 1).** Ye koi nahi bechta. Tumhara naam hi USP hai.
4. **Buyer #1:** lending protocol risk/governance teams (collateral whitelisting).
5. **Moat = DeFi Dependency Graph** (token → collateral → protocol → chain → TVL). Tool nahi, **data asset** banao.
6. **Exit thesis:** Chainalysis/Consensys/Zellic/TAC sab khareed rahe hain. **$50M realistic, $150M possible** agar recurring revenue + data ho (Alterya proof).
