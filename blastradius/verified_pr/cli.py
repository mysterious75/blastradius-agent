"""CLI shim — keeps ``python -m blastradius.verified_pr.cli`` working."""

from blastradius.verified_pr.pipeline import decide_verdict, main, run_verified_pr

__all__ = ["decide_verdict", "main", "run_verified_pr"]

if __name__ == "__main__":
    raise SystemExit(main())
