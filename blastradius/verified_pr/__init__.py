"""BlastRadius Verified PR — scan -> prove -> patch -> re-test -> merge/block.

One closed loop over a pull-request diff: static scan of the changed files,
sandbox exploit proof, auto-patch generation, re-test of each patch applied
to a scratch copy of the real tree, dependency-impact summary, and a single
fail-closed verdict (``MERGE`` / ``BLOCK`` / ``ERROR``).

The re-test step is what separates this from plain scan gates: a patch is
only trusted when the *same scanners* no longer flag the vulnerability after
the patch is applied to the real file tree — not when a snippet passes in
isolation. Anything that cannot be re-tested blocks the merge (fail-closed).
"""

from blastradius.verified_pr.models import (
    DependencyChange,
    RetestOutcome,
    VerifiedGate,
    VerifiedReport,
)
from blastradius.verified_pr.pipeline import main, run_verified_pr

__all__ = [
    "DependencyChange",
    "RetestOutcome",
    "VerifiedGate",
    "VerifiedReport",
    "main",
    "run_verified_pr",
]
