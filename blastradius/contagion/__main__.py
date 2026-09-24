"""Allow ``python -m blastradius.contagion``."""

from blastradius.contagion.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
