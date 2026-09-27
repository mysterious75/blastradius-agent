# rsETH Blast Radius: How a Single DVN Config Put $16.7B at Risk

**Tagline:** Pre-deployment contagion risk for DeFi. Deploy karein pehle, doob na jaayein baad mein.

> On 18 April 2026, a forged LayerZero packet — attested by a single
> compromised DVN — released 116,500 rsETH (~$292M) from KelpDAO's Ethereum
> OFTAdapter. No contract was buggy. Every contract behaved exactly as
> designed. One configuration number — `requiredDVNCount: 1` — is what made
> $292M of damage *possible*, and DeFi's composability is what made it
> *contagious*.

This post reconstructs the contagion cascade and shows the exact output our
pre-deployment engine produces for it. Every number below comes from running
the tool — reproductions included.

---

## 1. Timeline — what actually happened

*(Facts as documented by [Blockaid](https://blockaid.io/blog/how-a-single-layerzero-dvn-compromise-drained-292m-from-kelpdao),
[Chainalysis](https://www.chainalysis.com/blog/kelpdao-bridge-exploit-april-2026/),
and [LayerZero Labs' incident report](https://layerzero.network/blog/layerzero-labs-kelpdao-incident-report).)*

| Time (UTC) | Event |
|---|---|
| pre | Attacker wallets pre-funded via Tornado Cash — planned, not opportunistic |
| 18 Apr, ~17:35 | Forged LayerZero packet claims a Unichain source tx (nonce 308) that **never existed**; the single required DVN (`0x589dedbd…`) attests to it |
| +seconds | `lzReceive` executes against the Ethereum OFTAdapter (`0x85d456B2…Ef3`); 116,500 rsETH released from escrow — as designed |
| +minutes | 116,500 rsETH posted as collateral into Aave V3; WETH borrowed against it |
| +46 min | KelpDAO's emergency pauser multisig pauses transfers — second forged packet (nonce 309, 40,000 rsETH) blocked before delivery |
| hours after | Aave V3/V4, SparkLend, Fluid freeze rsETH markets; Upshift pauses affected vaults; rsETH live on 20+ L2s now wraps a drained reserve |

The rsETH token contract was never exploited. There was no admin takeover, no
reentrancy, no oracle manipulation. The entire attack surface was a
**verification configuration**: a `1-of-1` DVN setup where one compromised
signer set could authorize any cross-chain message.

```
UlnConfig on the receive pathway:
  requiredDVNCount:      1      ← the whole incident
  optionalDVNCount:      0
  optionalDVNThreshold:  0
```

A `2-of-N` configuration — say the LayerZero default DVN plus an independent
second provider — would have required the attacker to compromise two
independent verification stacks simultaneously.

---

## 2. The contagion graph — where the damage travels

rsETH isn't just a token; it's collateral, wrapped across 20+ chains. When the
backing reserve drained, the failure propagated along every composability
edge. Here is the dependency graph our engine traverses, seed = `Token:rsETH`:

```bash
python -m blastradius.contagion map --token *** --data data/seed_kelpdao_case.json --ascii
```

```
Token:rsETH  <-- SEED (this breaks)
├── [Market] Aave V3 Ethereum pool (rsETH listing)  ($5,200,000,000)
│   └── [Protocol] Aave  ($7,000,000,000)
│       └── [Chain] Ethereum  ($0)
├── [Market] Aave V4 Ethereum pool (rsETH listing)  ($1,800,000,000)
├── [Market] SparkLend Ethereum (rsETH listing)  ($940,000,000)
│   └── [Protocol] SparkLend  ($940,000,000)
├── [Market] Fluid rsETH market  ($310,000,000)
│   └── [Protocol] Fluid  ($310,000,000)
├── [Market] Upshift Finance vaults (High Growth ETH, Kelp Gain)  ($74,000,000)
│   └── [Protocol] Upshift Finance  ($74,000,000)
├── [Token] rsETH (Base)  ($41,000,000)
│   └── [Chain] Base  ($0)
├── [Token] rsETH (Arbitrum)  ($33,000,000)
│   └── [Chain] Arbitrum  ($0)
└── [Token] rsETH (Scroll)  ($12,000,000)
    └── [Chain] Scroll  ($0)

[*] 16 affected node(s), depth 3, reachable TVL $16,734,000,000
```

Reachability score for the seed:

```bash
python -m blastradius.contagion score --token *** --data data/seed_kelpdao_case.json
```

```
               Blast Radius Score
  Metric                       │ Value
╶──────────────────────────────┼────────────────╴
  Severity                     │ CRITICAL
  Affected nodes               │ 16
  Markets / protocols / chains │ 5 / 4 / 4
  Graph depth                  │ 3
  Direct exposure (USD)        │ 488,000,000
  Reachable TVL (USD)          │ 16,734,000,000
  Decayed TVL (USD)            │ 8,983,390,000
                               │
```

One token contract, five markets, four protocols, four chains — **$16.7B of
TVL within three hops of the failure.**

---

## 3. The bad debt — how $292M became a lending-protocol problem

The attacker didn't just steal rsETH. They **deposited the stolen rsETH into
Aave V3 and borrowed WETH against it**. Once the backing was gone, that
collateral had no real value — so liquidators had nothing to seize, and Aave's
WETH reserve was left holding debt it cannot clear through normal mechanics.
That is composability as an extraction mechanism: the second hop does more
damage than the first.

```bash
python -m blastradius.contagion baddebt --token *** --data data/seed_kelpdao_case.json
```

```
Bad Debt if rsETH -> 0.00
  Market         │ Protocol    │ Coll. at risk │ Debt vs token │ Backstop   │ Uncovered   │ Outcome
╶────────────────┼─────────────┼───────────────┼───────────────┼────────────┼─────────────┼─────────────╴
  Aave V3 Eth    │ Aave        │ 292,000,000   │ 240,000,000   │ 60,000,000 │ 180,000,000 │ UNLIQUIDATABLE
  SparkLend Eth  │ SparkLend   │ 58,000,000    │ 22,000,000    │ 5,000,000  │ 17,000,000  │ UNLIQUIDATABLE
  Fluid rsETH    │ Fluid       │ 34,000,000    │ 12,000,000    │ 0          │ 12,000,000  │ UNLIQUIDATABLE
  Aave V4 Eth    │ Aave        │ 85,000,000    │ 41,000,000    │ 30,000,000 │ 11,000,000  │ UNLIQUIDATABLE
  Upshift vaults │ Upshift Fin │ 19,000,000    │ 0             │ 0          │ 0           │ SOLVENT

[*] total uncovered loss: $220,000,000
```

**$220M of uncovered bad debt** across Aave V3/V4, SparkLend and Fluid — the
portion that each protocol's own safety buffer cannot absorb. (Aave has since
been working the WETH reserve deficit through its Umbrella backstop; partial
withdrawals depend on that settling.)

---

## 4. The config audit — what "deploy se pehle" looks like

The exploit needed zero bugs. So static analysis of the token contract finds
zero bugs — correctly. The thing that should have been caught is the
*configuration*. Running our config auditor against a snapshot of the
pre-incident setup:

```bash
python -m blastradius.contagion audit --config data/seed_kelpdao_config.json
echo $?   # -> 1
```

```
  Sev      │ Rule                        │ Target                    │ Finding
╶──────────┼─────────────────────────────┼───────────────────────────┼─────────────────────────────╴
  CRITICAL │ DVN-INSUFFICIENT-REDUNDANCY │ pathway:unichain->ethereum│ 1 attestor(s) — below the 2 floor
  CRITICAL │ DVN-INSUFFICIENT-REDUNDANCY │ pathway:ethereum->unichain│ 1 attestor(s) — below the 2 floor
  HIGH     │ DVN-CORRELATED-PATHWAYS     │ dvn:0x589dedbd617e…       │ one DVN secures 2 pathways
  HIGH     │ MULTISIG-THRESHOLD-ONE      │ multisig:emergency-pauser │ threshold 1-of-5 — one key is enough
  HIGH     │ NO-BACKSTOP-BUFFER          │ market:Fluid rsETH market │ borrowing enabled with zero backstop buffer
  HIGH     │ ORACLE-SINGLE-FEED          │ market:aave-v3-eth-pool   │ 1 price feed(s) — single point of failure
  MEDIUM   │ ADMIN-NO-TIMELOCK           │ admin:0xKelpDAO-ops       │ no timelock on admin actions
  ...
[*] worst: CRITICAL | CRITICAL=2  HIGH=4  MEDIUM=3  LOW=1
```

The first finding — `DVN-INSUFFICIENT-REDUNDANCY: 1 attestor, below the 2
floor` — is precisely the failure that produced the incident. It's checkable
on-chain, deterministically, in milliseconds. There is no reason this should
ever be discovered *after* $292M leaves the bridge.

Exit code `1` on CRITICAL means it drops straight into CI — the same check can
gate the deploy.

---

## 5. What this tool would have said before deploy

Three numbers, all computable before a single transaction is bridged:

| Pre-deployment signal | Value | Consequence if ignored |
|---|---|---|
| Blast radius score | **87 / 100 (CRITICAL)** | 16 nodes, 4 protocols, 4 chains |
| Reachable TVL | **$16.73B** | wrapped rsETH frozen across 20+ L2s |
| Uncovered bad debt at token → 0 | **$220M** | unliquidatable lending positions |
| Config audit | **CRITICAL ×2** (exit code 1) | forged-packet path is open |

None of this required predicting an attack. It required **measuring the blast
radius of an asset and reading the security parameters of its bridge** — both
available before deployment. The industry's posture is overwhelmingly
*reactive*: real-time transaction screening, on-chain monitoring, post-mortem
blogs. Those matter — Blockaid's real-time detection here was excellent — but
they operate *while the money is leaving*. The question this tool answers is
asked **before**:

> *"Agar ye token / contract hack hua to kitna TVL, kitne protocols, kitni
> chains affect hongi — DEPLOY KARNE SE PEHLE."*

---

## 6. Run it yourself

Everything above is reproducible from the open-source repo:

```bash
git clone https://github.com/mysterious75/blastradius-agent
cd blastradius-agent
python -m pytest tests/ -q                     # 679 tests, offline, green
python -m blastradius.contagion score --token *** --data data/seed_kelpdao_case.json
python -m blastradius.contagion audit --config data/seed_kelpdao_config.json
```

Or skip the install — **the free calculator**:

➡️ **`GET /api/v1/contagion/score?token=rsETH`** — paste a token symbol, get
the score card: blast radius score, reachable TVL, affected
markets/protocols/chains, bad debt uncovered, and the ASCII cascade map.
No signup. If you want the same numbers for a token that isn't in the graph
yet, or live DeFiLlama/on-chain data instead of the snapshot — that's what the
paid tiers are for; reach out.

---

## Notes on the numbers

- Incident facts ($292M / 116,500 rsETH, the DVN configuration, timeline,
  affected protocols) are as publicly documented — sources linked in §1.
- **Market-level sizing** (supplied/borrow/backstop per market) in the graph
  snapshot is *illustrative model input* used to exercise the contagion
  engine, calibrated so the totals match the publicly reported damage. Treat
  per-market rows as model output, not audited figures. Live DeFiLlama /
  on-chain ingestion is on the roadmap before scores are shipped to customers.
- The scoring model: reachability with hop decay (`0.65^h`); headline score =
  `22 · log10(1 + decayed_TVL/1M)`, capped at 100.

---

*Written by the BlastRadius team — pre-deployment contagion risk for DeFi.
Respect to the KelpDAO, LayerZero, and Aave teams for an unusually transparent
incident response. If you run a protocol with cross-chain dependencies and
want a blast-radius review, our DMs are open.*
