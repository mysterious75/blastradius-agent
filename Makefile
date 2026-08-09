.PHONY: setup test scan blast server docker

# BlastRadius Agent — Make targets (Phase 6)
# Usage: TARGET and REPO can be overridden, e.g. make scan TARGET=https://github.com/org/repo

setup:
	python -m venv venv
	venv/bin/pip install -U pip
	venv/bin/pip install cai-framework -e .[dev]

test:
	python -m pytest tests/ -v

scan:
	python -m blastradius.hunter --target $(TARGET)

blast:
	python -m blastradius.blast_radius --repo $(REPO)

server:
	uvicorn blastradius.github_app.webhook:app --reload

docker:
	docker build -t blastradius-sandbox sandbox/
