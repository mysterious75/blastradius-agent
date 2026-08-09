# BlastRadius Agent — main image.
FROM python:3.11-slim

WORKDIR /app

COPY . .

RUN pip install --no-cache-dir -e ".[all]"

EXPOSE 8080 8000

CMD ["python", "-m", "blastradius.dashboard"]
