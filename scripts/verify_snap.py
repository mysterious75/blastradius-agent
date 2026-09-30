"""Verify ingest_snapshot output shape."""

import json
import os

p = os.path.join(os.environ["TEMP"], "snapsnap", "blast-graph.json")
d = json.load(open(p, encoding="utf-8"))
print("provenance:", sorted(d["provenance"].keys()))
print("nodes:", len(d["graph"]["nodes"]), "edges:", len(d["graph"]["edges"]))
print("has disclaimer:", "disclaimer" in d["provenance"])
