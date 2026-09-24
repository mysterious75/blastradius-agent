# 🔴 BlastRadius — Research & Strategy

Ye folder product/strategy decisions ka record hai. Sab public sources se
compiled; citations har document ke end mein.

| # | Document | Kya hai |
|---|---|---|
| 00 | `00-README.md` (ye) | Index |
| 01 | `01-COMPETITIVE-RESEARCH.md` | **Master dossier** — competitors, market map, techniques, datasets, GitHub/HF/Reddit/Twitter signals, gap analysis |
| 02 | `02-MARKET-VALUATIONS-AND-MA.md` | **Valuation + M&A/IPO table** aur KelpDAO $292M blast-radius case study |
| 03 | `03-ARTIFACTS-INDEX.md` | Downloaded papers/reports ki inventory + jo paywall mein phase unka workaround |
| 04 | `04-DESIGN-DECISIONS.md` | **Kya banaya, kyun banaya** — `blastradius/contagion/` ke design decisions |

---

## Ek nazar mein — strategy

**Positioning:** *Pre-deployment contagion risk for DeFi.*
> *"Ek contract ka exploit kitna TVL le doobe? Hum deploy se pehle batate hain."*

**White space:** "blast radius / contagion scoring" koi product nahi bechta —
na Blockaid (sirf blog), na Gauntlet/Chaos Labs (sirf parameter tuning),
na academia (sirf papers). Details `01` ke §10 mein.

**Moat:** tool nahi, **data asset** — `DeFi Dependency Graph`
(token → collateral market → protocol → chain → TVL). Kyunki tool-only
products marte hain (MythX acquire hoke sunset ho gaya; Code4rena $1M pe bik
gaya). Details `02` ke §4 mein.

**Founding case study:** KelpDAO / LayerZero DVN, 18 Apr 2026 — $292M,
ek `1-of-1` DVN config ki wajah se. Poora contagion map `02` ke §2 mein.

**Buyer #1:** lending protocols ki risk/governance teams (collateral
whitelisting) → phir insurers → phir bridge/L2 risk teams.

---

## ⚖️ Scope note

Ye research **market/product** ke liye hai. Attack techniques sirf utna hi
refer kiye gaye hain jitna competitive landscape samajhne ke liye zaroori tha —
koi offensive capability, payload, ya evasion guidance yahan nahi hai.

`blastradius/contagion/` **defensive pre-deployment risk scoring** hai:
dependency mapping + solvency projection. Authorized-testing-only policy repo
ke `DISCLAIMER.md` / `SECURITY.md` ke saath hi applicable hai.
