"""CLI entrypoint — ``python -m blastradius.verified_pr``."""

from blastradius.verified_pr.pipeline import main

if __name__ == "__main__":
    raise SystemExit(main())
