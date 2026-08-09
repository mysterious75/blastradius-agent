# BlastRadius exploit sandbox image.
# Build:  docker build -t blastradius-sandbox sandbox/
# Run:    docker run --rm --network none --read-only --memory=128m --runtime=runsc -v <tmp>:/app blastradius-sandbox
# No network egress: enforced at runtime with --network none; the image itself
# only ships the two PoC files and the runtime deps.

FROM python:3.11-slim

RUN pip install --no-cache-dir requests flask sqlalchemy

COPY target_code.py /app/
COPY exploit_poc.py /app/

WORKDIR /app

CMD ["python", "exploit_poc.py"]
