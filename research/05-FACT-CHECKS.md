# 📌 Fact-Checks — Citable Numbers (verified 2026-09-27)

Har blog post / forum post / deck mein cite karne se pehle ye table dekho.
Ye **web-verified** hain (search + primary sources) — `01-COMPETITIVE-RESEARCH.md`
ka supporting layer.

| Claim | Verified value | Source | Verified |
|---|---|---|---|
| KelpDAO incident date/loss | 18 Apr 2026, 116,500 rsETH ≈ **$292M**, 1-of-1 DVN (0x589dedbd…), OFTAdapter 0x85d456B2…Ef3 | blockaid.io blog (19 Apr 2026); chainalysis.com (23 Apr); layerzero.network incident report (20 May) | ✅ |
| Second packet blocked | nonce 309, 40,000 rsETH (~$100M), emergency pauser acted **+46 min** | blockaid.io | ✅ |
| Attacker attribution | Lazarus-linked (Chainalysis); Tornado Cash pre-funding | chainalysis.com / blockaid.io | ✅ |
| Extraction mechanic | stolen rsETH → Aave V3 collateral → WETH borrowed → unliquidatable bad debt | blockaid.io (tx hashes published) | ✅ |
| KelpDAO TVL at exploit | ~$1.07B ETH LRT TVL (2nd-largest EigenLayer participant) | blockaid.io | ✅ |
| Affected protocols | Aave V3/V4, SparkLend, Fluid frozen; Upshift paused; rsETH on 20+ chains | blockaid.io / defiprime.com / openzeppelin.com | ✅ |
| H1 2026 crypto losses | **$1.1B across 212 exploits** (record incident count); key compromises overtook contract bugs | Blockaid H1 2026 report — unchained, thedefiant (29 Jul 2026), crypto.news (28 Jul 2026) | ✅ |
| Gauntlet Series C | **$125M**, led by SBI Holdings, **9 Jul 2026** (total ~$169M) | gauntlet.xyz press release; fintech.global (14 Jul 2026) | ✅ |
| Hexagate exit | Chainalysis acquisition ≈ **$60M** (on ~$8.6M raised) | forgeglobal.com (Chainalysis IPO page); Architect Partners M&A Alert (17 Sep 2026) | ✅ |
| Alterya exit | Chainalysis acquisition **$150M** (13 Jan 2025) | calcalistech; decurity.io M&A tracker | ✅ |

## Writing rules

1. **Incident facts** — cite Blockaid/Chainalysis/LayerZero, "as publicly documented".
2. **Market sizing in `data/seed_kelpdao_case.json`** — ILLUSTRATIVE per the
   snapshot's own `_note`. Never present per-market rows as audited figures;
   totals (16.73B / 220M) are model output calibrated to public damage reports.
3. **Exit comps** — "estimated" where the source says estimated (Hexagate).
4. **KelpDAO causality** — no contract bug; config (`requiredDVNCount: 1`) was
   the attack surface. Say exactly that; don't imply a LayerZero protocol flaw.
