/* BlastRadius calculator — client-side port of blastradius/contagion/scoring.py.
 *
 * Original work, MIT licensed with the repository.
 *
 * The algorithms here intentionally mirror the Python so that a reader can
 * verify the numbers in the browser against `python3 -m blastradius.contagion`.
 * Anything labelled "derived" is computed locally; it is not a DeFiLlama
 * figure. See data/blast-graph.json -> provenance.
 */

(function () {
  "use strict";

  var DATA_URL = "data/blast-graph.json";
  var HOP_DECAY = 0.65; /* must match scoring.score_blast_radius */

  /* ---------- loading ---------- */

  function nodeKey(kind, name) {
    return kind + ":" + name;
  }

  function loadGraph() {
    return fetch(DATA_URL, { cache: "no-cache" }).then(function (r) {
      if (!r.ok) throw new Error("HTTP " + r.status + " for " + DATA_URL);
      return r.json();
    }).then(function (snap) {
      var payload = snap.graph || snap;
      var nodes = {};
      var out = {}; /* src -> [edge] : damage flows along src -> dst */
      (payload.nodes || []).forEach(function (n) {
        nodes[n.id] = n;
      });
      (payload.edges || []).forEach(function (e) {
        (out[e.src] = out[e.src] || []).push(e);
      });
      return {
        raw: payload,
        provenance: snap.provenance || null,
        nodes: nodes,
        out: out,
        successors: function (id) { return out[id] || []; }
      };
    });
  }

  /* ---------- blast radius (mirrors graph.DeFiContagionGraph.blast_radius) ---------- */

  function blastRadius(g, seedId, maxDepth) {
    maxDepth = maxDepth || 5;
    var seen = {}; seen[seedId] = true;
    var queue = [{ id: seedId, hop: 0, path: [seedId] }];
    var entries = [];

    while (queue.length) {
      var cur = queue.shift();
      if (cur.hop >= maxDepth) continue;
      g.successors(cur.id).forEach(function (edge) {
        var hit = edge.dst;
        if (seen[hit]) return;
        seen[hit] = true;
        var node = g.nodes[hit];
        if (!node) return;
        var path = cur.path.concat([hit]);
        entries.push({
          node_id: hit,
          kind: node.kind,
          name: node.name,
          hop: cur.hop + 1,
          tvl_usd: node.tvl_usd || 0,
          via: edge.kind,
          path: path
        });
        queue.push({ id: hit, hop: cur.hop + 1, path: path });
      });
    }
    return { seed_id: seedId, entries: entries };
  }

  function namesOfKind(radius, kind) {
    var seen = {};
    radius.entries.forEach(function (e) {
      if (e.kind === kind) seen[e.name] = true;
    });
    return Object.keys(seen).sort();
  }

  /* ---------- scoring (mirrors scoring.score_blast_radius) ---------- */

  function score(g, seedId, maxDepth) {
    var radius = blastRadius(g, seedId, maxDepth);
    var direct = 0;
    g.successors(seedId).forEach(function (e) {
      if (e.kind !== "COLLATERAL_IN") return;
      var m = g.nodes[e.dst];
      if (!m || m.kind !== "Market") return;
      direct += m.meta && m.meta.token_supplied_usd != null
        ? m.meta.token_supplied_usd : (m.tvl_usd || 0);
    });
    var decayed = 0, reachable = {}, total = 0;
    radius.entries.forEach(function (e) {
      decayed += e.tvl_usd * Math.pow(HOP_DECAY, e.hop);
      if (!reachable[e.node_id]) { reachable[e.node_id] = true; total += e.tvl_usd; }
    });
    var severity = "INFO";
    if (decayed >= 5e8) severity = "CRITICAL";
    else if (decayed >= 1e8) severity = "HIGH";
    else if (decayed >= 1e7) severity = "MEDIUM";
    else if (decayed > 0) severity = "LOW";

    return {
      seed_id: seedId,
      node_count: radius.entries.length,
      market_count: namesOfKind(radius, "Market").length,
      protocol_count: namesOfKind(radius, "Protocol").length,
      chain_count: namesOfKind(radius, "Chain").length,
      depth: radius.entries.reduce(function (a, e) { return Math.max(a, e.hop); }, 0),
      direct_exposure_usd: direct,
      reachable_tvl_usd: total,
      decayed_tvl_usd: decayed,
      severity: severity,
      radius: radius
    };
  }

  /* ---------- bad debt (mirrors scoring.simulate_token_collapse) ----------
   *
   *   bad_debt  = debt_against_token * (1 - price_ratio)
   *   uncovered = max(0, bad_debt - backstop_buffer)
   *   liquidatable = bad_debt <= 0
   *
   * backstop_buffer_usd is 0 for every live-ingested market (no free API
   * publishes safety-module balances), so uncovered is an UPPER BOUND.
   */

  function badDebt(g, seedId, priceRatio) {
    priceRatio = priceRatio == null ? 0 : priceRatio;
    var rows = [];
    g.successors(seedId).forEach(function (e) {
      if (e.kind !== "COLLATERAL_IN") return;
      var m = g.nodes[e.dst];
      if (!m || m.kind !== "Market") return;
      var meta = m.meta || {};
      var atRisk = meta.token_supplied_usd != null ? meta.token_supplied_usd : (m.tvl_usd || 0);
      var debt = meta.debt_against_token_usd || 0;
      var buffer = meta.backstop_buffer_usd || 0;
      var bad = debt * (1 - priceRatio);
      var uncovered = Math.max(0, bad - buffer);
      var proto = "";
      g.successors(m.id).forEach(function (h) {
        if (h.kind === "PART_OF" && g.nodes[h.dst]) proto = g.nodes[h.dst].name;
      });
      rows.push({
        market_id: m.id,
        market_name: m.name,
        protocol: proto,
        collateral_at_risk_usd: atRisk,
        debt_against_token_usd: debt,
        backstop_buffer_usd: buffer,
        bad_debt_usd: bad,
        uncovered_loss_usd: uncovered,
        liquidatable: bad <= 0,
        ltv: meta.ltv,
        outcome: bad <= 0 ? "SOLVENT" : "UNLIQUIDATABLE"
      });
    });
    rows.sort(function (a, b) {
      return (b.uncovered_loss_usd - a.uncovered_loss_usd) ||
        a.market_name.localeCompare(b.market_name);
    });
    return rows;
  }

  /* ---------- ASCII cascade (mirrors cli._ascii_map) ---------- */

  function asciiMap(radius, seedId) {
    var children = {};
    radius.entries.forEach(function (e) {
      var parent = e.path.length >= 2 ? e.path[e.path.length - 2] : seedId;
      (children[parent] = children[parent] || []).push(e);
    });
    var lines = [seedId + "   <-- SEED (this breaks)"];

    function walk(parent, prefix) {
      var kids = (children[parent] || []).slice().sort(function (a, b) {
        return (a.hop - b.hop) || (b.tvl_usd - a.tvl_usd);
      });
      kids.forEach(function (kid, i) {
        var last = i === kids.length - 1;
        var branch = last ? "\u2514\u2500\u2500 " : "\u251c\u2500\u2500 ";
        var cont = last ? "    " : "\u2502   ";
        lines.push(prefix + branch + "[" + kid.kind + "] " + kid.name +
          "   ($" + fmt(kid.tvl_usd) + ")");
        walk(kid.node_id, prefix + cont);
      });
    }
    walk(seedId, "");
    return lines.join("\n");
  }

  /* ---------- formatting ---------- */

  function fmt(n) {
    return (n || 0).toLocaleString("en-US", { maximumFractionDigits: 0 });
  }
  function usd(n) {
    var v = n || 0;
    if (Math.abs(v) >= 1e9) return "$" + (v / 1e9).toFixed(2) + "B";
    if (Math.abs(v) >= 1e6) return "$" + (v / 1e6).toFixed(1) + "M";
    if (Math.abs(v) >= 1e3) return "$" + (v / 1e3).toFixed(1) + "K";
    return "$" + fmt(v);
  }

  window.BlastRadius = {
    loadGraph: loadGraph,
    blastRadius: blastRadius,
    score: score,
    badDebt: badDebt,
    asciiMap: asciiMap,
    namesOfKind: namesOfKind,
    fmt: fmt,
    usd: usd,
    nodeKey: nodeKey
  };
})();
