# BlastRadius exploit sandbox image.
# Build:  docker build -t blastradius-sandbox sandbox/
# Run:    docker run --rm --network none --read-only --memory=128m --runtime=runsc -v <tmp>:/app blastradius-sandbox
# No network egress: enforced at runtime with --network none. PoC and target
# files are supplied per-run via the /app volume mount — never baked in.
# Runtime deps cover what reconstructed PoCs import (jinja2 for SSTI,
# lxml for XXE, plus the usual web/DB suspects).

FROM python:3.11-slim

RUN pip install --no-cache-dir requests flask sqlalchemy jinja2 lxml defusedxml

WORKDIR /app

CMD ["python", "exploit_poc.py"]
