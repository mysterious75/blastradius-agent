# BlastRadius Agent — main image (least-privilege runtime).
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Non-root runtime: the scanner never needs root, and a compromised
# dashboard/API process must not be able to modify the image or pip state.
RUN groupadd --system app \
    && useradd --system --gid app --create-home --home-dir /home/app app

COPY --chown=app:app . .
RUN pip install --no-cache-dir -e ".[all]"

USER app

EXPOSE 8080 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/', timeout=3)" || exit 1

CMD ["python", "-m", "blastradius.dashboard"]
