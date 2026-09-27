"""Free public contagion calculator — pre-deployment blast-radius score card.

The growth wedge from ``research/01-COMPETITIVE-RESEARCH.md``: a no-signup
score for any token in the dependency graph. One question in, one number out:

    "Agar ye token hack hua to kitna TVL niche jaayega?"

Endpoints (public, no auth — this is the marketing surface, not the paid API):

    GET /api/v1/contagion/score?token=rsETH    -> score card JSON
    GET /api/v1/contagion/map?token=rsETH      -> ASCII cascade tree
    GET /                                       -> simple HTML frontend

The heavy lifting lives in :mod:`blastradius.contagion` — this module only
resolves a token, formats a JSON envelope, and serves one HTML page.

``blast_radius_score`` is a 0..100 headline derived from the engine's decayed
exposure: ``round(22 * log10(1 + decayed_tvl_usd / 1e6))``, i.e. ~22 points per
order of magnitude of decayed exposure, capped at 100. It exists for humans
(the A+/A/B/C warranty bands in the roadmap) — the engine's own severity
stays the machine-readable ``risk_level``.
"""

from __future__ import annotations

import datetime as _dt
import math
import os
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse

from blastradius.contagion.graph import DeFiContagionGraph
from blastradius.contagion.schema import NodeKind
from blastradius.contagion.scoring import (
    score_blast_radius,
    simulate_token_collapse,
)

__all__ = [
    "router",
    "build_calculator_app",
    "compute_score_card",
    "normalized_score",
    "ascii_map",
    "default_data_path",
    "load_graph",
]

# `<repo root>/blastradius/web/calculator.py` -> `<repo root>/data/...`
_REPO_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_DATA = _REPO_ROOT / "data" / "seed_kelpdao_case.json"

# Price-drop scenarios shown on the score card (post-collapse price ratio).
_SCENARIO_DROP_RATIOS = (0.25, 0.50, 0.75, 0.90)

router = APIRouter()


# ---------------------------------------------------------------------------
# Graph loading / token resolution
# ---------------------------------------------------------------------------


def default_data_path() -> Path:
    """Graph snapshot path — ``BLASTRADIUS_CONTAGION_DATA`` overrides the seed."""
    env = os.getenv("BLASTRADIUS_CONTAGION_DATA", "").strip()
    return Path(env) if env else _DEFAULT_DATA


def load_graph(path: Optional[Path] = None) -> DeFiContagionGraph:
    data = Path(path) if path is not None else default_data_path()
    if not data.is_file():
        raise HTTPException(
            status_code=503,
            detail=f"contagion dataset not configured: {data}",
        )
    return DeFiContagionGraph.from_json(data)


def resolve_seed(graph: DeFiContagionGraph, token: str) -> str:
    """Token symbol -> seed node id (case-insensitive), or 404."""
    wanted = token.strip()
    if not wanted:
        raise HTTPException(status_code=400, detail="token is required")
    exact = graph.seed_id(NodeKind.TOKEN, wanted)
    if graph.backend.node(exact) is not None:
        return exact
    for node in graph.backend.all_nodes():
        if node.kind is NodeKind.TOKEN and node.name.lower() == wanted.lower():
            return node.id
    known = sorted(n.name for n in graph.backend.all_nodes() if n.kind is NodeKind.TOKEN)
    raise HTTPException(
        status_code=404,
        detail=f"unknown token {wanted!r}; known: {', '.join(known) or 'none'}",
    )


# ---------------------------------------------------------------------------
# Score card
# ---------------------------------------------------------------------------


def normalized_score(decayed_tvl_usd: float) -> int:
    """0..100 headline score from decayed exposure (22 points per OOM)."""
    if decayed_tvl_usd <= 0:
        return 0
    score = round(22.0 * math.log10(1.0 + decayed_tvl_usd / 1e6))
    return max(0, min(100, score))


def _usd(value: float) -> int:
    """Whole dollars — JSON consumers get integers, not floats with noise."""
    return int(round(value))


def compute_score_card(graph: DeFiContagionGraph, token: str) -> dict:
    """Build the calculator JSON envelope for ``token``."""
    seed = resolve_seed(graph, token)
    score = score_blast_radius(graph, seed)
    rows = simulate_token_collapse(graph, seed, price_ratio=0.0)

    scenarios = {}
    for drop in _SCENARIO_DROP_RATIOS:
        ratio = 1.0 - drop
        scenarios[f"{int(drop * 100)}%"] = _usd(
            sum(r.uncovered_loss_usd for r in simulate_token_collapse(graph, seed, ratio))
        )

    node = graph.backend.node(seed)
    return {
        "token": node.name if node is not None else token,
        "blast_radius_score": normalized_score(score.decayed_tvl_usd),
        "reachable_tvl_usd": _usd(score.reachable_tvl_usd),
        "affected_markets": score.market_count,
        "affected_protocols": score.protocol_count,
        "affected_chains": score.chain_count,
        "bad_debt_uncovered_usd": _usd(sum(r.uncovered_loss_usd for r in rows)),
        "risk_level": score.severity,
        "generated_at": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        # extras (non-breaking; the keys above are the stable contract)
        "seed_id": seed,
        "affected_nodes": score.node_count,
        "graph_depth": score.depth,
        "direct_exposure_usd": _usd(score.direct_exposure_usd),
        "decayed_tvl_usd": _usd(score.decayed_tvl_usd),
        "bad_debt_scenarios_usd": scenarios,
    }


def ascii_map(graph: DeFiContagionGraph, token: str) -> str:
    """ASCII cascade tree — same shape as ``contagion map --ascii``."""
    seed = resolve_seed(graph, token)
    radius = graph.blast_radius(seed)

    lines = [f"{seed}  <-- SEED (this breaks)"]

    def walk(parent: str, prefix: str = "") -> None:
        children = [e for e in radius.entries if len(e.path) >= 2 and e.path[-2] == parent]
        for i, entry in enumerate(children):
            last = i == len(children) - 1
            node = graph.backend.node(entry.path[-1])
            name = node.name if node is not None else entry.path[-1]
            kind = node.kind.value if node is not None else "?"
            lines.append(f"{prefix}{'└──' if last else '├──'} [{kind}] {name}  (${entry.tvl_usd:,.0f})")
            walk(entry.path[-1], prefix + ("    " if last else "│   "))

    walk(seed)
    lines.append("")
    lines.append(
        f"[*] {radius.node_count} affected node(s), depth {radius.depth}, "
        f"reachable TVL ${radius.total_tvl_usd:,.0f}"
    )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# HTTP surface
# ---------------------------------------------------------------------------


@router.get("/api/v1/contagion/score")
async def contagion_score(token: str = Query(..., min_length=1, max_length=64)):
    """Public score card. Free tier — rate limiting lives in the paid API."""
    graph = load_graph()
    return JSONResponse(compute_score_card(graph, token))


@router.get("/api/v1/contagion/map")
async def contagion_map(token: str = Query(..., min_length=1, max_length=64)):
    graph = load_graph()
    return JSONResponse({"token": token, "ascii_map": ascii_map(graph, token)})


@router.get("/", response_class=HTMLResponse, include_in_schema=False)
async def calculator_page() -> HTMLResponse:
    return HTMLResponse(_PAGE)


_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>BlastRadius — Pre-Deployment Contagion Score</title>
<style>
  :root { color-scheme: dark; }
  body { margin: 0; font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
         background: #0d1117; color: #e6edf3; display: flex; justify-content: center; }
  main { max-width: 880px; width: 100%; padding: 48px 24px; }
  h1 { font-size: 1.6rem; margin: 0 0 4px; }
  .tag { color: #8b949e; margin: 0 0 32px; font-size: .95rem; }
  form { display: flex; gap: 8px; margin-bottom: 24px; }
  input { flex: 1; padding: 12px 14px; font: inherit; border: 1px solid #30363d;
          border-radius: 8px; background: #161b22; color: #e6edf3; }
  button { padding: 12px 22px; font: inherit; font-weight: 600; cursor: pointer;
           border: none; border-radius: 8px; background: #f85149; color: #fff; }
  button:hover { background: #da3633; }
  .card { border: 1px solid #30363d; border-radius: 12px; padding: 24px;
          background: #161b22; margin-bottom: 16px; display: none; }
  .score-row { display: flex; align-items: baseline; gap: 16px; }
  .score { font-size: 3.2rem; font-weight: 700; }
  .badge { padding: 4px 12px; border-radius: 999px; font-size: .85rem; font-weight: 700; }
  .CRITICAL { background: #f8514933; color: #f85149; }
  .HIGH { background: #d2992233; color: #d29922; }
  .MEDIUM { background: #bb800933; color: #e3b341; }
  .LOW, .INFO { background: #3fb95033; color: #3fb950; }
  table { width: 100%; border-collapse: collapse; margin-top: 16px; }
  td { padding: 8px 4px; border-top: 1px solid #21262d; }
  td:last-child { text-align: right; font-weight: 600; }
  pre { background: #0d1117; border: 1px solid #30363d; border-radius: 12px;
        padding: 20px; overflow-x: auto; font-size: .85rem; line-height: 1.5; }
  .err { color: #f85149; display: none; }
  .foot { color: #6e7681; font-size: .8rem; margin-top: 32px; }
</style>
</head>
<body>
<main>
  <h1>🔴 BlastRadius Contagion Calculator</h1>
  <p class="tag">How much TVL could a failure of this token touch — before you deploy.</p>
  <form id="f">
    <input id="token" placeholder="token symbol, e.g. rsETH" value="rsETH" autocomplete="off">
    <button type="submit">Score</button>
  </form>
  <p class="err" id="err"></p>
  <div class="card" id="card">
    <div class="score-row">
      <div class="score" id="score">–</div>
      <div>
        <div><strong id="tokenname"></strong> blast radius score</div>
        <span class="badge" id="badge">–</span>
      </div>
    </div>
    <table>
      <tr><td>Reachable TVL</td><td id="tvl"></td></tr>
      <tr><td>Bad debt uncovered (token → 0)</td><td id="baddebt"></td></tr>
      <tr><td>Affected markets / protocols / chains</td><td id="affected"></td></tr>
      <tr><td>Graph depth</td><td id="depth"></td></tr>
    </table>
    <table id="scen"></table>
  </div>
  <pre id="map" style="display:none"></pre>
  <p class="foot">Market-level figures come from the current graph snapshot;
     see data/README notes before citing externally. Generated by BlastRadius v1.0.0.</p>
</main>
<script>
const usd = n => "$" + n.toLocaleString("en-US");
document.getElementById("f").addEventListener("submit", async (e) => {
  e.preventDefault();
  const t = document.getElementById("token").value.trim();
  const err = document.getElementById("err");
  err.style.display = "none";
  try {
    const [s, m] = await Promise.all([
      fetch("/api/v1/contagion/score?token=" + encodeURIComponent(t)).then(r => r.json().then(j => { if (!r.ok) throw new Error(j.detail || r.status); return j; })),
      fetch("/api/v1/contagion/map?token=" + encodeURIComponent(t)).then(r => r.json()),
    ]);
    document.getElementById("score").textContent = s.blast_radius_score;
    document.getElementById("tokenname").textContent = s.token;
    const badge = document.getElementById("badge");
    badge.textContent = s.risk_level;
    badge.className = "badge " + s.risk_level;
    document.getElementById("tvl").textContent = usd(s.reachable_tvl_usd);
    document.getElementById("baddebt").textContent = usd(s.bad_debt_uncovered_usd);
    document.getElementById("affected").textContent =
      s.affected_markets + " / " + s.affected_protocols + " / " + s.affected_chains;
    document.getElementById("depth").textContent = s.graph_depth;
    const scen = Object.entries(s.bad_debt_scenarios_usd || {})
      .map(([k, v]) => `<tr><td>Uncovered loss at ${k} price drop</td><td>${usd(v)}</td></tr>`).join("");
    document.getElementById("scen").innerHTML = scen;
    document.getElementById("map").textContent = m.ascii_map;
    document.getElementById("card").style.display = "block";
    document.getElementById("map").style.display = "block";
  } catch (ex) {
    err.textContent = String(ex.message || ex);
    err.style.display = "block";
    document.getElementById("card").style.display = "none";
    document.getElementById("map").style.display = "none";
  }
});
</script>
</body>
</html>
"""


def build_calculator_app():
    """Standalone app: ``uvicorn blastradius.web.calculator:build_calculator_app --factory``."""
    from fastapi import FastAPI

    app = FastAPI(
        title="BlastRadius Contagion Calculator",
        version="1.0.0",
        description="Free pre-deployment blast-radius score for DeFi tokens.",
    )
    app.include_router(router)
    return app
