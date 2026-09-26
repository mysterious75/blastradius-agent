"""python -m blastradius.export — findings export CLI (csv|json|sarif|html|markdown)."""

from blastradius.export.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
