"""python -m blastradius.ci — CI security & quality gate entry point."""

from blastradius.ci.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
