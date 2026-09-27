# Aave Governance Forum Post Template — BlastRadius Contagion Score

**How to use:** copy the structure below, fill the `[BRACKETS]`, attach the
tool output verbatim. First post = the rsETH retroactive analysis (example
appended). Keep the tone technical and collaborative — this audience (Risk
Stewards, BGD Labs, Chaos Labs) reads numbers, not marketing.

**Target thread:** `governance.aave.fi` → *Risk* category
**Suggested subject:** `BlastRadius Contagion Score for [TOKEN] Collateral Listing`
**CC/mention candidates:** Risk Steward, BGD Labs, Chaos Labs, LlamaRisk —
they are already engaged in listing threads.

---

## Template

### Summary

We ran a pre-deployment **contagion blast-radius analysis** for `[TOKEN]` as a
proposed Aave `[V3/V4]` `[CHAIN]` collateral asset. This complements (does not
replace) the market risk work already done by Chaos Labs / Gauntlet: instead
of price parameters, it answers the composability question — *if this token
fails, how much of Aave's TVL is within reach of the failure, and how much debt
survives with no collateral behind it?*

Tool: open-source, reproducible — every number below can be re-derived from the
commands included.

### 1. Blast radius score

| Metric | Value |
|---|---|
| Blast radius score | `[0–100]` (`[LOW/MEDIUM/HIGH/CRITICAL]`) |
| Reachable TVL | `$[X]` |
| Direct exposure to `[TOKEN]` | `$[X]` |
| Affected markets / protocols / chains | `[M] / [P] / [C]` |
| Graph depth | `[D]` |

```
[VERBATIM OUTPUT: python -m blastradius.contagion score --token [TOKEN] --data [SNAPSHOT]]
```

Contagion map (`map --ascii`):

```
[VERBATIM ASCII TREE]
```

### 2. Bad-debt simulation

What survives as unliquidatable debt if `[TOKEN]` falls — per price drop, net
of each market's stated backstop buffer (`debt × drop − backstop`, floored at 0):

| `[TOKEN]` price drop | Uncovered bad debt |
|---|---|
| 50% | `$[X]` |
| 75% | `$[X]` |
| 90% | `$[X]` |
| → 0 (token worthless) | `$[X]` |

```
[VERBATIM OUTPUT: python -m blastradius.contagion baddebt --token [TOKEN] --data [SNAPSHOT]]
```

The mechanic is the one that left Aave's WETH reserve carrying unliquidatable
bad debt after the KelpDAO drain (18 Apr 2026): collateral vanishes, debt does
not, liquidators have nothing to seize. The `backstop_buffer_usd` column is
what Safety Module / Umbrella is assumed to absorb.

### 3. Config audit — bridge / oracle / admin surface

Contagion is not only about the token contract. `[TOKEN]`'s cross-chain and
oracle configuration determines whether an *unbacked* supply can ever appear:

```
[VERBATIM OUTPUT: python -m blastradius.contagion audit --config [CONFIG SNAPSHOT]]
echo $?   # exit 1 = CRITICAL present (CI-gateable)
```

Checklist for listing discussion:

- [ ] Bridge verification: `[N]`-of-`[M]` DVN/multisig attestation — single attester = single point of forgery
- [ ] Oracle: single feed? staleness / deviation bounds set?
- [ ] Backstop buffer sized to the borrow against this collateral
- [ ] Emergency actions: multisig threshold ≥ 2, timelock on parameter changes

### 4. Recommendation

Choose one and justify from the numbers above:

- **APPROVE** — score ≤ 50, no CRITICAL config findings, uncovered bad debt
  within stated backstop at the 90% drop scenario.
- **CONDITIONAL** — score 51–70, or backstop insufficient at 90% drop.
  Conditions: `[e.g. supply cap X until bridge config reaches 2-of-N; isolation
  mode; second oracle feed]`.
- **REJECT / DEFER** — score ≥ 71 or any CRITICAL config finding on the path
  that creates unbacked supply (bridge mint, upgradeable admin, single oracle).

### Reproducibility

```bash
git clone https://github.com/mysterious75/blastradius-agent
python -m blastradius.contagion score  --token [TOKEN] --data [SNAPSHOT]
python -m blastradius.contagion baddebt --token [TOKEN] --data [SNAPSHOT]
python -m blastradius.contagion audit   --config [CONFIG SNAPSHOT]
```

Free public calculator (no install): `GET /api/v1/contagion/score?token=[TOKEN]`

---

## Appendix — filled example (rsETH, retroactive)

*This is the shape a first, retroactive post takes: same engine, seeded with
the KelpDAO incident graph (published snapshot; market-level sizing
illustrative, incident facts per Blockaid/Chainalysis/LayerZero reports).*

**Subject:** BlastRadius Contagion Score for rsETH — retroactive analysis
(18 Apr 2026 incident)

**1. Score:** 87/100 **CRITICAL** — reachable TVL **$16.73B**, 5 markets /
4 protocols / 4 chains, depth 3, direct exposure $488M.

**2. Bad debt (uncovered, net of backstop):**

| rsETH price drop | Uncovered bad debt |
|---|---|
| 50% | $72.0M |
| 75% | $141.25M |
| 90% | $188.5M |
| → 0 | $220.0M |

At token → 0: Aave V3 $180M, SparkLend $17M, Fluid $12M, Aave V4 $11M —
all **UNLIQUIDATABLE**.

**3. Config audit:** exit code **1** — `DVN-INSUFFICIENT-REDUNDANCY` CRITICAL on
both receive pathways (1 attestor, below the 2 floor), plus correlated DVN
across pathways, `1-of-5` emergency multisig, single oracle feed on the Aave
V3 listing. The `1-of-1` DVN is exactly what allowed the forged packet.

**4. Recommendation (retrospective):** would have been **REJECT/DEFER** on
config grounds alone at listing time — and **CONDITIONAL** at best on contagion
grounds (score 87, uncovered bad debt 3× the Aave V3 backstop buffer).

The point of posting this retroactively: all four checks were computable
*before* the listing and *before* the exploit. The tool is open source and the
scores are publicly queryable; we'd like listing discussions to include this
dimension by default. Happy to run the same analysis for any asset currently in
the listing pipeline — turn-around is minutes.
