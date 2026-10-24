# 🥊 Competitive Landscape — AppSec / AI Code Security (2026-10-04)

**Parent:** `01-COMPETITIVE-RESEARCH.md`, `06-DEEP-DIVE-COMPETITORS.md` (DeFi side covered there)
**Trigger:** "hamara tool jo specific kaam karta hai, uske according competitors nikalo — wo kya kar rahe hain, hum kya karein ki industry mein tike aur investor paise lagaye"
**Method:** live web research (funding databases, vendor announcements, docs) — Oct 2026

---

## 0. Verdict (5 lines)

1. **Hamara exact combo koi nahi bechta:** deterministic scanners + *executed* sandbox PoC + auto-patch-and-reverify + live dynamic checks + DeFi contagion + fail-closed scope — ek box mein. Sab log iske *tukde* bechte hain.
2. **Sabse khatarnaak trend: "AI likhega, AI check karega, AI fix karega"** — CodeRabbit ($1.5B), Endor ($208M), Semgrep (Series D $100M, $722M val), Snyk+Claude. Market velocity ki taraf bhaag raha hai, proof ki taraf nahi.
3. **Wahi hamara wedge hai:** sabke paas hypotheses hain, kisi ke paas `[VULNERABLE]` execution marker nahi. Triager/investor dono ko "demonstrably exploitable" chahiye — Vercel $1M challenge ne ye likh ke de diya (static-analysis-only = no bounty).
4. **Consolidation chal rahi hai:** Qwiet acquired, Protect AI → Palo Alto ($500M). Acquire hone layak bano ya acquire karne layak — dono ke liye proof + data asset chahiye.
5. **Investor ko chahiye:** paid-pilot logo, NRR/usage numbers, aur ek aisi cheez jo incumbent copy na kar sake. Hamari wo cheez: **execution-proof + DeFi blast-radius data** — dono mehnat se bante hain, slide se nahi.

---

## 1. Competitor map — hamari capability vs kaun kya karta hai

### A. Static detection (hamara `hunter/` + `scanners/`: 19 types, 14 scanners)

| Player | Funding / val | Kya karta hai | Humse farq |
|---|---|---|---|
| **Semgrep** | Series D $100M (Feb 2025), val $722M, total $193M | OSS engine + SAST/SCA/secrets + Guardian (AI-gen code) + Multimodal AI + MCP server + supply-chain malware firewall | Engine best-in-class, community moat; **lekin proof nahi** — findings hypotheses hain. Hamara sandbox-execution unke "Multimodal" ka missing half hai |
| **Snyk (+Claude, May 2026)** | Public-ish scale, 4,500 customers | DeepCode AI (85% autofix claim), reachability-based prioritization, Evo (AI asset discovery) | Autofix % marketing hai, verification story kamzor. Hamara PatchLoop *re-runs the exploit after every fix* — ye line investor deck mein jaani chahiye |
| **Endor Labs** | Series B $93M (Apr 2025), total ~$188-208M; ARR 30x, 5M+ apps, 1M scans/week | Reachability SCA → full AppSec platform, agentic AI fix, AURI (agent harness security) | Sabse tez badhta competitor. Reachability ≈ hamara "candidate vs confirmed" lekin unka proof dynamic-execution nahi. Direct overlap zone |
| **Qwiet AI** (ex-ShiftLeft) | **Acquired Sep 2025** | Code property graphs + AI AutoFix, 95% faster remediation claim | Consolidation ka saboot — acquirer ne reachability+autofix kharida |

### B. AI code review / PR gate (hamara naya `blastradius/ci/` gate)

| Player | Funding / val | Kya karta hai | Humse farq |
|---|---|---|---|
| **CodeRabbit** | Series C $143M @ **$1.5B** (Aug 2026); 2M repos, 13M PRs reviewed | Independent AI review + Triage + Change Stack + Security + autofix; "Agentic Change Management" | Category king. **Lekin: AI hi decider hai, deterministic policy engine nahi; proof nahi, aur pricing per-dev per-month ($24-90). Hamara gate: LLM kabhi PASS/FAIL decide nahi karta + execution-proof + free/self-hosted** |
| **Greptile** | ~$180M valuation talk (YC) | AI review, codebase-aware | Review-only, no prove/patch loop |
| **GitHub Copilot Autofix** | Bundled | CodeQL findings → autofix suggestions | Closed ecosystem, GitHub-only; hamara gate provider-neutral (GitHub + Bitbucket already) |
| **Mobb** | Seed $5.4M+ | SAST-ingest → auto-fix (Snyk/Checkmarx/GHAS compatible) | Fix-only layer, apna detection nahi; hamara PatchLoop + verify unse behtar kahani hai |
| **Pixee** | Seed $15M (May 2025, Decibel/Wing) | Agentic triage + trusted fixes, 76% merge rate, deterministic+AI hybrid | Positioning hamare sabse kareeb ("deterministic + agentic"). Unke paas enterprise GTM hai; hamare paas proof + DeFi |

### C. ASPM / platform (hamara dashboard + API + DB + chains)

| Player | Signal | Kya karta hai | Humse farq |
|---|---|---|---|
| **Apiiro** | Gartner AST MQ 2025: **#1 in ASPM** | Deep code analysis, XBOM inventory, AutoFix agent (Aug 2025) | Enterprise ASPM standard; ham ASPM nahi — ham *finding-to-proof-to-patch* engine hain. Complementary, competitive nahi (abhi) |
| **Cycode** | Gartner MQ debut + Frost Leader 2025 | AST+ASPM+SSCS convergence, 120+ integrations, MCP server, AI Exploitability Agent | Platform breadth mein humse 10x aage; depth (proof) mein peeche |
| **OX Security** | IDC MarketScape Leader ASPM 2025 | Evidence-based prioritization (reachability/exploitability), no-code remediation, PR gates | "Evidence" unka reachability hai; hamara evidence *execution* hai — ek level up |
| **Endor** | (upar) | Same platform motion | Same |

### D. AI/runtime firewall (adjacent — hamara future surface)

| Player | Signal | Note |
|---|---|---|
| **Protect AI → Palo Alto** | **$500M acquisition (Jul 2025)** → Prisma AIRS | Exit comp sabse relevant: model scanning + red-teaming + runtime. Hamara `hunt-llm-ai` skill + MCP server is taraf ishara karte hain |
| **HiddenLayer** | Series B **$100M** (Sep 2026, Delta-v; total ~$150M) | Agentic Runtime Security + **Agent Harness Security** (prompt injection, secret exposure, unsafe commands in coding agents) |
| **Lakera, Cranium, AIM** | Active | AI-firewall lane bheed wali hai — yahan mat ghuso abhi |

### E. DeFi / smart-contract (hamara `contagion/` + `solidity.py` — 06 mein detail hai)

| Player | Signal | Humse farq |
|---|---|---|
| **CertiK** | ~$1B val, $140M+ raised, Skynet monitoring, 31k vulns | Audit factory + monitoring; **koi blast-radius/contagion product nahi** |
| **Hypernative** | Series B $40M (2025), $100B+ protected, 200+ customers, EF customer | Real-time prevention (post-deploy). Hum pre-deploy (contagion scoring) — complementary; integration angle |
| **Hexens** | Glider Monitor (CTEM for Web3), $120B protected claim | Monitoring + audit; no contagion math |
| **Cantina / CodeHawks / Code4rena / Sherlock** | Competition model ($25k-77k pots) | Human networks; hamara automation unka leverage ban sakta hai (pre-screening tool), competitor nahi |
| **LlamaRisk / BA Labs** | Manual governance risk reviews (06 mein detail) | Hamara automation target — unka deliverable hamara product |

---

## 2. Competitors ABHI kya kar rahe hain (pattern, Oct 2026)

1. **"Secure AI-generated code" sabka headline hai** (Semgrep Guardian, Endor AURI, Snyk Evo, HiddenLayer Harness). AI likhega → volume 10x → sabko review bottleneck dikh raha hai.
2. **Autofix sab bechte hain, verification koi nahi** (Pixee 76% merge rate, Snyk 85% autofix, CodeRabbit autofix loops). *"Fix laga, exploit dobara chalaya, tabhi merge"* — ye line kisi ke marketing mein nahi hai. Hamare paas hai.
3. **Policy/governance layer ban raha hai moat** (CodeRabbit "Agentic Change Management", Endor policy-at-moment-of-action). Hamara deterministic policy engine + fail-closed scope isi lane mein hai — chhota par sahi direction.
4. **Consolidation:** acquire ho rahe hain reachability + autofix + AI-runtime wale. Buyer (Palo Alto jaisa) "proof" kharidega jab samjhega ki hypotheses commodity hain.
5. **MCP har jagah:** Semgrep, Cycode, CodeRabbit sab MCP server de rahe hain — hamara MCP server (7 tools) table stakes cover karta hai, differentiator nahi.
6. **DeFi mein paisa monitoring ki taraf beh raha hai** (Hypernative $40M, Hexens Glider) — pre-deploy contagion scoring abhi bhi khaali plot hai (06 ka verdict kayam).

---

## 3. Hum kya karein — industry mein tikne ke liye (ordered)

**P0 — Proof ko product banao (yehi moat hai):**
- Har finding ke saath `[VULNERABLE]` execution artifact + re-verified patch — ye already hai; isko **demo-able** banao (one-command: scan → PoC video/log → patch → re-run).
- Benchmark ko public scoreboard banao (F1 static/dynamic + proven-count). Koi competitor public proof-benchmark nahi dikhata — Semgrep "80% fewer FPs" bolta hai, number nahi dikhata.

**P0 — Ek paid pilot logo (investor ka pehla sawal):**
- 2-3 design-partner teams (DeFi protocol ya AI-startup) free pilot par, unke real repo par chalao, unke quote lo. "91% remediation time" jaise Pixee wale numbers hamare paas hone chahiye — hamara engine ye measure kar sakta hai (PatchLoop already counts retries).

**P1 — AI-generated-code lane pakdo (saste mein):**
- `Guardian`-style mode: AI-diff detector + stricter rules on agent-written code. Hamara scanner already language-aware hai; "agent-written" flag bas ek label hai.
- CodeRabbit se ladna mat — **unke neeche lago**: CodeRabbit review karta hai, hum prove + patch karte hain. Integration story ("pair with your reviewer") partnership/acquisition dono kholti hai.

**P1 — DeFi plot par kabza (koi nahi hai wahan):**
- Contagion score ko LlamaRisk-style deliverable banao: per-token listing risk report (P1.3 wala template) automated. Manual wale $X lete hain per review; hum per-day automated.
- Hypernative/CertiK se lado mat — **pre-deploy (hum) + post-deploy monitoring (wo)** = full lifecycle story. Partnership deck banao.

**P2 — Distribution jahan developers hain:**
- GitHub Action + Bitbucket (done), VS Code/JetBrains extension (missing — Semgrep/Cycode dono ke paas hai), MCP (done).
- Free tier for OSS (CodeRabbit ne $10M lagaye OSS free par — goodwill + top-of-funnel; hamara self-hosted free already hai, bas announce karo).

**Kabhi mat karna:** AI-firewall lane (bheed + paisa dono udhar hain), apna foundation model, enterprise sales team time se pehle.

---

## 4. Investor paisa kyun lagaye — pitch spine

1. **Thesis (1 line):** "AI 10x code likhega; saare scanners hypotheses bechte hain — hum execution-proof bechte hain, patch samet."
2. **Traction dikhao, slide nahi:** live benchmark numbers (16/16, 23/23, proven-counts), design-partner quotes, remediation-time-measured (PatchLoop data), OSS adoption (free self-hosted).
3. **Market comps (Oct 2026, verified):** CodeRabbit $1.5B · Semgrep $722M · Endor ~$188M raised · Pixee $15M seed · Protect AI $500M exit · Hypernative $40M Series B. Hamara ask inke beech kahin — proof + DeFi data ke saath.
4. **Moat (copy karne mein mehnat):** (a) sandbox-proof engine + verified-patch loop, (b) DeFi contagion graph + incident data asset, (c) deterministic policy/fail-closed IP. Koi bhi teeno ek saath nahi rakhta.
5. **Exit paths:** acquirer list — Snyk/Semgrep/Endor (proof gap), Palo Alto/Wiz (DeFi + proof), CertiK/Hypernative (pre-deploy gap). Consolidation chal rahi hai; proof-asset wale acquire hote hain.
6. **Ask + use of funds:** 18-month runway → 2 enterprise pilots → public proof-benchmark → DeFi listing-risk product. Milestone-gated.

---

## 5. Risks / imaandaar notes

- Funding/valuation figures secondary sources (Tracxn/PitchBook excerpts) se hain — deck mein daalne se pehle primary se verify karo.
- "Koi nahi karta" claims Oct-2026 snapshot hain; landscape tez badalta hai — ye file har quarter refresh karo.
- Sabse bada risk execution hai, idea nahi: proof-engine + 2 pilot bina paisa nahi aayega, chahe deck kitna bhi achha ho.
