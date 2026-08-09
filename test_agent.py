"""Week-3 deliverable: run the BlastRadius agent through CAI.

Usage:
    python test_agent.py "Scan https://example.com/page?id=1 for SQL injection"
"""

import asyncio
import sys

from blastradius.agent import run_scan


async def main():
    prompt = sys.argv[1] if len(sys.argv) > 1 else (
        "Scan https://example.com/page?id=1 for SQL injection"
    )
    output = await run_scan(prompt)
    print(output)


if __name__ == "__main__":
    asyncio.run(main())
