"""Live cross-check: fetch real Aave markets, build graph, report stats."""
import sys

sys.path.insert(0, r"D:\deepseek\blastradius-agent")
from blastradius.contagion.loaders import aave
from blastradius.contagion.schema import EdgeKind, NodeKind
from collections import Counter

markets = aave.fetch_markets(chain_ids=[1, 42161, 8453])
print("markets fetched:", [(m.get("name"), len(m.get("reserves", []))) for m in markets])
g = aave.build_graph_from_aave(markets)
n = g.backend.all_nodes()
e = g.backend.all_edges()
print("nodes:", len(n), Counter(x.kind.value for x in n))
print("edges:", len(e), Counter(x.kind.value for x in e))
r = g.blast_radius(g.seed_id(NodeKind.TOKEN, "wstETH"))
print("wstETH blast radius:", r.node_count, "nodes,",
      len(r.names_of_kind(NodeKind.MARKET)), "markets")
