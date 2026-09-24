# Data Attribution & Legal Notes

Ye document batata hai ki data kahan se aata hai, kya humne add kiya hai, aur
kis tarah ke claims **nahi** kiye gaye. Agar tum is repo ko fork ya commercial
use kar rahe ho, to ye padh lena.

---

## 1. Market data — DeFiLlama

| Field | Source endpoint |
|---|---|
| project, chain, symbol, pool id, TVL | `https://yields.llama.fi/pools` |
| total supply, total borrow, LTV, borrowable, borrow factor, debt ceiling, underlying tokens | `https://yields.llama.fi/lendBorrow` |
| protocol TVL by chain, oracle breakdown, audit links, hack history | `https://api.llama.fi/protocol/{slug}` |

- **Provider:** [DeFiLlama](https://defillama.com) — an open-source project that
  publishes this data through free public APIs.
- **How we use it:** figures are copied **unmodified**. The only transformation
  is a documented join of `/pools` with `/lendBorrow` on `pool` id, plus field
  renames recorded in `blastradius/contagion/loaders/collateral.py`.
- **Attribution:** rendered in the site footer and embedded in every snapshot
  under `provenance`.
- **Independence:** DeFiLlama does not endorse this project and is not
  affiliated with it. We use their name for identification of the data source only.
- **Rate limiting:** our loader enforces a minimum interval between requests and
  sends an identifying `User-Agent`. Do not remove those.

> Agar tum dataset redistribute karte ho, to `provenance` block ke saath hi karo.

---

## 2. Derived figures — humne banaya, DeFiLlama ka nahi

Ye sab `blastradius/contagion/scoring.py` (aur uska browser mirror
`docs/assets/app.js`) locally compute karte hain:

- `bad_debt_usd`
- `uncovered_loss_usd`
- `decayed_tvl_usd`, `reachable_tvl_usd`, blast-radius `severity`
- config-audit `Finding`s

**Inhe DeFiLlama figures mat samajhna.** Formulas `docs/calculator.html` pe
khud likhe hain taaki verify kar sako.

**Known limitation (hamesha disclose kiya gaya hai):** safety-module / backstop
balances koi free API publish nahi karta. Live-ingested markets mein
`backstop_buffer_usd = 0` hota hai, isliye `uncovered_loss_usd` ek **upper
bound** hai, forecast nahi.

---

## 3. Incident references

`docs/index.html` aur `docs/deck.html` ek public incident (April 2026) ka
**factual outline** dete hain with a link to the published post-mortem.

- Sirf **facts** paraphrase kiye gaye hain (dates, amounts, sequence, root-cause
  category). Koi **prose copy nahi** ki gayi, koi figure invent nahi kiya.
- Incident ke amounts aur unki analysis unki respective parties ki hain.
- Source link har jagah diya gaya hai.

---

## 4. Names & trademarks

Is project mein jitne bhi protocols, companies, chains ya tools naam se liye
gaye hain (Aave, Compound, Morpho, SparkLend, Fluid, LayerZero, DeFiLlama,
Chainlink, Base, Arbitrum, Scroll, ...) — **sirf identification ke liye**.

- Kisi ke saath **affiliation ya endorsement claim nahi** kiya gaya.
- Koi **third-party logo, mark, ya brand asset** use nahi kiya gaya. Site pe sirf
  apna original CSS/HTML hai.
- "BlastRadius" yahan ek descriptive term ke roop mein use hota hai (blast radius
  ek standard systems/security concept hai).

---

## 5. Code licensing & copyright

- Naya code (`blastradius/contagion/`, `docs/`, `scripts/ingest_live.py`) **original
  work** hai aur repo ke **MIT** license ke under aata hai.
- Koi third-party code copy nahi kiya gaya. Jo algorithms reference kiye gaye hain
  (blast-radius traversal, bad-debt projection) wo standard graph/arithmetic hain
  aur yahan apne se implement kiye gaye hain.
- `docs/assets/style.css` aur `docs/assets/app.js` bhi original hain — koi
  third-party font, icon set, ya CSS framework bundle nahi kiya gaya (system fonts
  use kiye hain).
- Academic papers jo `research/` mein cite kiye gaye hain unke **citations** hain,
  copies nahi.

---

## 6. What this tool does *not* do

Suspend/ban risk se bachne ke liye — aur kyunki ye sahi kaam hai — ye project:

- ❌ kisi third-party system pe **traffic generate nahi** karta
- ❌ koi **vulnerability scanning, exploitation, payload** nahi karta
- ❌ koi **HTML scraping** nahi karta — sirf published JSON APIs
- ❌ koi **secret / API key** repo mein nahi rakhta
- ❌ GitHub Actions mein koi **external target** hit nahi karta
- ✅ sirf **published configuration aur market data** padhta hai, aur risk report
  deta hai taaki deploy se pehle fix ho sake

Repo ka `DISCLAIMER.md` aur `SECURITY.md` — **authorized use only** — isi project
pe bhi lagu hota hai.

---

## 7. Disclaimer

**Not financial, legal, or investment advice.** Saare figures point-in-time
estimates hain aur likhte hi stale ho jaate hain. Koi warranty nahi — MIT license
ke `AS IS` clause ke mutabik.

Koi bhi listing decision apni due diligence ke baad hi lo. Agar kisi data point
pe doubt ho to asli source (DeFiLlama / on-chain record) se verify karo.
