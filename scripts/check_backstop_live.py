"""Live cross-check: full backstop read."""

import sys
import time

sys.path.insert(0, r"D:\deepseek\blastradius-agent")
time.sleep(2)
from blastradius.contagion.loaders import backstop  # noqa: E402 - sys.path bootstrap above

out = backstop.fetch_backstops()
for k, v in out.items():
    print(f"{k:22} ${v:,.0f}")
print(f"TOTAL: ${sum(out.values()):,.0f}")
