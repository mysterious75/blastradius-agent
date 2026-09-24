# 🧠 Design Decisions — `blastradius/contagion/`

**Date:** 2026-09-24 · **Status:** v0.1 shipped (18 tests passing)
**Input:** `01-COMPETITIVE-RESEARCH.md` + `02-MARKET-VALUATIONS-AND-MA.md`

Ye document har bade decision aur uske *kyun* ka record hai.

---

## D1. Kya banaya — aur kya **nahi** banaya

### ✅ Banaya: pre-deployment contagion graph (`contagion/`)

Research ke §10 (gap analysis) ne dikhaya ki **"blast radius scoring" ka koi
product nahi hai**. Sab log *retrospective* kaam karte hain:

| Kaun | Kya karta hai | Kab |
|---|---|---|
| Blockaid | Transaction simulation, phir blog post-mortem | **hack ke baad** |
| TxRay (arXiv 2602.01317) | Root-cause + executable PoC | **hack ke baad** |
| Hexagate / Hypernative | Real-time on-chain alerts | **hack ke dauraan** |
| Gauntlet / Chaos Labs | Economic parameter tuning | pre-deploy, lekin **exploit contagion nahi** |

→ **BlastRadius ka slot: hack SE PEHLE.** *"Agar ye token fail ho jaye to
kitna TVL, kitne protocols, kitni chains jaayengi?"*

### ❌ Nahi banaya (jaan-boojh ke)

| Cheez | Kyun nahi abhi | Research ref |
|---|---|---|
| Real-time on-chain monitoring | Ring 2 already bahut bhara hai (Hexagate→Chainalysis, Hypernative, Forta, Blockaid). Yahan jaana = unke ghar mein ladai | §1 Ring 2 |
| Automated scanner ka aur ek SAST | Slither/Mythril/Echidna commodity hain. Margins ghat rahe hain (Cyberscope 98% margins pe bhi sirf $1.4M rev) | §3 |
| LLM audit model | ChainGPT, CredShields, LLMBugScanner, SmartLLM sab kar rahe hain. **Model commodity hai, data nahi** | §5 |
| Offensive / evasion tooling | Out of scope (see `DISCLAIMER.md`) | — |

---

## D2. Edge direction — **damage flow** (jo sabse bada design call tha)

> **Convention:** `src` breaks → `dst` is damaged.
> Blast radius = **forward traversal** (`successors()`).

**Kyun:** repo ke existing `blastradius/blast_radius/graph.py` ka
`(Package)-[:USED_IN]->(Repo)` exactly yahi karta hai — `query_blast_radius`
forward `MATCH` hai. Naye module ko same convention follow karna chahiye tha,
na ki opposite.

**⚠️ Pehli baar mein maine ye ulta kar diya tha** (`dependent -> dependency`
+ reverse traversal). Tests ne pakda: cascade 1 hop pe ruk jaati thi, kyunki
`(Market)-[:HOSTED_BY]->(Protocol)` mein `Protocol` *successor* tha na ki
*predecessor*. Fix karke edge kinds bhi rename kiye taaki direction padhne pe
khud samajh aaye:

| Purana naam (ambiguous) | Naya naam | Direction |
|---|---|---|
| `ACCEPTS` (`Market→Token`) | `COLLATERAL_IN` (`Token→Market`) | token toota → market insolvent |
| `HOSTED_BY` (`Market→Protocol`) | `PART_OF` (`Market→Protocol`) | market ka bad debt → protocol hurt |
| `BACKED_BY` (`Token→Token`) | `BACKS` (`Token→Token`) | backing tooti → derivative worthless |
| `PRICED_FROM` (`Market→Oracle`) | `PRICES` (`Oracle→Market`) | feed fail → market mispriced |
| `DEPLOYED_ON` | `DEPLOYED_ON` (`Protocol→Chain`) | unchanged ✓ |
| `WRAPPED_ON` | `WRAPPED_ON` (`Token→Chain`) | unchanged ✓ |

**Sabak:** "relationship name pair describe karta hai" ambiguity banata hai.
"impact direction" explicit hona chahiye.

---

## D3. Do scoring models, jaan-boojh ke alag

Research (KelpDAO case, `02` §2) ne dikhaya ki do alag sawaal hain jinhe
mix karna ghalat result deta:

1. **`score_blast_radius()`** — *damage kitni door tak jayegi?*
   Reachability + TVL exposure, hop-decay ke saath (`0.65^hop`).
   Ye **pre-deployment** sawaal hai (collateral listing approve karni hai ya nahi).

2. **`simulate_token_collapse()`** — *token zero ho jaye to kitna bad debt
   bachega jise liquidation clear nahi kar sakta?*
   ```
   bad_debt     = debt_against_token × (1 − price_ratio)
   uncovered    = max(0, bad_debt − backstop_buffer)
   liquidatable = bad_debt ≤ 0
   ```

**Kyun alag:** blast radius ek *reachability* problem hai; insolvency ek
*balance-sheet* problem hai. Dono ko ek score mein milaoge to na graph
samajh aayega na solvency.

`backstop_buffer_usd` field isliye hai — yahi wo "Aave Umbrella backstop"
mechanic hai jiske wajah se KelpDAO ke baad Aave ke WETH withdrawals
settle hone tak locked the (`02` §2).

---

## D4. Node model — `Token → Market → Protocol → Chain` (+ `Oracle`)

**Kyun 5 kinds:**
- **Token** — the thing that breaks (rsETH)
- **Market** — *jahan collateral listing hoti hai* (Aave V3 ETH pool ka rsETH listing). Ye asli unit of risk hai, "protocol" nahi — ek protocol ke alag-alag listings alag risk rakhte hain.
- **Protocol** — risk/reputation/recovery ka aggregating layer (governance yahan react karta hai)
- **Chain** — exposure ka geographic dimension (KelpDAO case mein 20+ L2s)
- **Oracle** — alag failure mode, alag edge (`PRICES`)

**Ek important modeling choice:** `Market` node **single-asset nahi** hai —
"Aave V3 Ethereum pool (rsETH listing)" = poora pool, jisme rsETH ek
collateral hai. Isliye alag fields hain:
- `token_supplied_usd` — kitna collateral *is token mein hai*
- `debt_against_token_usd` — us collateral ke against kitna borrow hua
- `backstop_buffer_usd` — safety module / umbrella kitna absorb kar sakta hai

Ye teeno milke hi sahi bad-debt number dete hain. (`Market` ka `tvl_usd`
poore pool ka hai, isliye wo blast-radius TVL mein jaata hai, bad-debt mein nahi.)

---

## D5. Data source — seed snapshot + DeFiLlama loader

- **`data/seed_kelpdao_case.json`** — KelpDAO incident ka graph. Incident
  facts real hain (Blockaid post-mortem se); **market-level sizing illustrative
  hai** aur file mein `_note` se clearly flagged hai.
- **`blastradius/contagion/loaders/defillama.py`** — live TVL ke liye, **stdlib
  only** (`urllib`), koi nayi dependency nahi. Public read-only API, no key.

**Kyun stdlib-only:** repo ki dependency surface chhoti rakhni thi, aur loader
optional path hai — core graph/scoring bina network ke kaam karta hai
(isliye tests offline hain).

---

## D6. Testing policy — no network, no database

`tests/test_contagion.py` — 18 tests, sab offline. Loader deliberately test
nahi hota (network code hai).

Khaas tests jo design ko lock karti hain:
- `test_blast_radius_travels_damage_forward` — D2 convention
- `test_blast_radius_kind_filter_does_not_prune_traversal` — filter sirf
  *return* kya hota hai control kare, *traversal* nahi (nahi to hop-2 nodes
  milna band ho jaate)
- `test_cycle_does_not_loop_forever` — LRT/LST nesting cyclic ho sakti hai
- `test_bad_debt_matches_kelpdao_mechanic` — real incident ke numbers se lock
- `test_oracle_failure_reaches_every_market_it_prices` — alag failure mode

**Regression check:** `tests/test_blast_radius.py` (existing, 10 tests) bhi
pass — naye module ne kuch nahi toda.

---

## D7. Bug jo tests ne pakda (worth documenting)

**Node id ≠ display name.** Snapshot JSON mein slug ids hain
(`Market:aave-v3-eth-pool`) jabki `name` display label hai
(`Aave V3 Ethereum pool (rsETH listing)`). `from_dict` pehle id ko `name` se
derive kar raha tha → sab edges orphan → blast radius 0 nodes.

Fix: `from_dict` ab `id` / `src` / `dst` ko **verbatim** use karta hai, aur
`add_node(..., node_id=...)` explicit id accept karta hai.

**Sabak:** slug aur label ko mat milao. Ids stable rakhna seekho.

---

## 📌 Agla kadam (priority order)

Research §10 ke hisaab se asli moat **data asset** hai, tool nahi.

1. **DeFi Dependency Graph ka ingestion** — collateral whitelists scrape/read
   (Aave, Compound, SparkLend, Morpho...) + bridge/OFT configs + oracle feeds.
   Yahi wo graph hai jo koi nahi bechta.
2. **Config Auditor** — `requiredDVNCount < 2 && optionalDVNCount == 0` jaise
   patterns. KelpDAO mein ye **1 line** pakad leta ($292M bach jaate).
3. **Bad-debt numbers ko real data** se replace karo (DeFiLlama + on-chain reads).
4. **Free public "blast radius calculator"** → lead magnet (research §11).
5. **License fix** (research §10): MIT → AGPL + commercial dual license.

---

## References

- Blockaid — *How a Single LayerZero DVN Compromise Drained $292M from KelpDAO* (19 Apr 2026)
- Decurity — *Web3 Security M&As and IPOs* (11 Feb 2026)
- Gudgeon et al. — *The Decentralized Financial Crisis: Attacking DeFi* (2020)
- *Contagion in Decentralized Lending Protocols: A Case Study of Compound V2* — ACM FC 2024 (`10.1145/3605768.3623544`)
- TxRay — *Agentic Postmortem of Live Blockchain Attacks* — arXiv `2602.01317`
- ChainSec — *Documented Timeline of DeFi Exploits* (191 incidents / $6.12B)
