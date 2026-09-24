# 📥 Artifacts Index

**Collected:** 2026-09-24 · Parent: `research/BLASTRADIUS-COMPETITIVE-RESEARCH.md`

---

## ✅ Downloaded & verified (valid PDF)

| File | Size | Source | Kyo important |
|---|---|---|---|
| `txray-agentic-postmortem-live-blockchain-attacks.pdf` | 845 KB | arXiv `2602.01317` (Jan 2026) | 🔴 **#1 technical rival.** 114 DeFiHackLabs incidents → root-cause + executable PoC (105/114). Blastradius ke "prove" step jaisa. Padho + differentiate karo |
| `llmbugscanner-smart-contract-auditing.pdf` | 1.1 MB | arXiv `2512.02069` (Nov 2025) | LLM + fine-tuning se smart-contract vuln detection |
| `auditing-agents-finetuning-smart-contracts.pdf` | 1.5 MB | arXiv `2403.16073` | **1,734 labelled vulnerable functions from 263 real audits** ka dataset approach — tumhara training corpus recipe |
| `iota-101-blockchain-usecases-handbook.pdf` | 17 MB | IOTA Foundation 2025 | Chainalysis ke web3 security acquisitions ka reference |

## 📝 Hand-written extracts

| File | Kya hai |
|---|---|
| `key-extracts-valuation-and-MA.md` | M&A/IPO valuation table + KelpDAO $292M blast-radius case notes |

---

## ⛔ Auto-download fail hue (paywall / bot-wall) — manually grab karo

| Paper / Report | URL | Kyun fail | Kaise lo |
|---|---|---|---|
| **Contagion in Decentralized Lending Protocols (Compound V2)** | `dl.acm.org/doi/10.1145/3605768.3623544` | ACM paywall | 🎓 University/VPN ya author ka arXiv version search karo (`arxiv "Contagion in Decentralized Lending Protocols"`). **Ye tumhara mathematical core hai — zaroor lo** |
| **CPMMX — Automated Attack Synthesis for CPMMs** | `dl.acm.org/doi/10.1145/3728872` | ACM paywall | Same. Authors ko email karo — CS mein sab log dete hain |
| **HOUSTON — Real-Time Anomaly Detection of Attacks on Ethereum DeFi** | `escholarship.org/uc/item/55g1753d` | eScholarship bot-wall | Browser se kholo → PDF. Ya NDSS symposium archive mein dhoondho |
| **Mythos-Class AI and Blockchain Systemic Risk** | `preprints.org/manuscript/202605.0128` | Preprints download gate | Browser se "Download PDF" click karo. **"blast radius" ko rated quantity banata hai** |
| **DeFi security survey (S2667295226000024)** | `sciencedirect.com/science/article/pii/S2667295226000024` | Elsevier paywall | Koi open-access mirror dhoondho ya Sci-Hub policy ke hisaab se |
| **OpenZeppelin / S&P Global M&A Alert** | `architectpartners.com/wp-content/uploads/2026/09/OpenZeppelin-SP-Global-MA-Alert.pdf` | Architect Partners ne block kiya | Site pe register karke lo — **OZ ka acquisition chal raha hai, valuation milega** |
| **Sherlock — Top 10 Auditing Companies 2026** | `sherlock.xyz/post/top-10-best-smart-contract-auditing-companies-in-2026` | Client-side JS render | Browser se padho |
| **SmartLLM** | `huggingface.co/papers/2502.13167` | HTML page | `arxiv.org/pdf/2502.13167` try karo |

---

## 🌐 Live data sources (download nahi — scrape/API karo)

| Source | URL | Format | Use |
|---|---|---|---|
| **ChainSec DeFi Exploits Timeline** | `chainsec.io/defi-hacks` | HTML table | 🥇 **191 exploits, $6.12B.** Scrape karke labelled dataset banao |
| **DeFiHackLabs** | `github.com/SunWeb3Sec/DeFiHackLabs` | Foundry PoCs (Solidity) | `git clone` — reproduced exploits ka corpus |
| **DeFiVulnLabs** | `github.com/SunWeb3Sec/DeFiVulnLabs` | Solidity | Synthetic vuln patterns |
| **awesome-web3-security** | `github.com/gmh5225/awesome-web3-security` | Markdown + agent skills | `git clone` |
| **DeFiLlama Hacks** | `defillama.com/hacks` | HTML/API | Loss amounts |
| **rekt.news Leaderboard** | `rekt.news/leaderboard` | HTML | Post-mortems |
| **Chaos Labs Aave proposal** | `governance.aave.com/t/updated-proposal-chaos-labs-risk-simulation-platform/10025` | Forum | Competitor methodology |
| **Blockaid KelpDAO post-mortem** | `blockaid.io/blog/how-a-single-layerzero-dvn-compromise-drained-292m-from-kelpdao` | Blog | **Tumhara reference methodology + founding case** |
| **IdoBn DVN-check gist** | `gist.github.com/IdoBn/7753f16fdb6810b11c5c87cdf11f8aa0` | bash | Blockaid ka DVN config checker (basic hai — tum isse better banao) |
| **Decurity open data** | `decurity.io/data` | — | Incident data |

## 🤗 Hugging Face assets (clone/download)

| Asset | Command / URL |
|---|---|
| `Chain-GPT/Solidity-LLM` (2.78B) | `huggingface-cli download Chain-GPT/Solidity-LLM` |
| `credshields/Solidity-CodeGen-v0.1` | `huggingface-cli download credshields/Solidity-CodeGen-v0.1` |
| `WhitzardAgent/CyberSecurity-1M` dataset | `huggingface-cli download --repo-type dataset WhitzardAgent/CyberSecurity-1M` |

---

## ⚖️ License note
Sab upar wale **research/reference** ke liye collect kiye gaye hain (fair-use / public research papers).
Koi bhi code/data apni product mein daalne se pehle **uska license check karo** — DeFiHackLabs, Slither, Echidna sab alag-alag licence pe hain.
