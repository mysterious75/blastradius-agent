.PHONY: setup test scan blast server docker install publish tag clean lint format

# BlastRadius Agent — Make targets
# Usage: TARGET and REPO can be overridden, e.g. make scan TARGET=https://github.com/org/repo

setup:
	python -m venv venv
	venv/bin/pip install -U pip
	venv/bin/pip install cai-framework -e .[dev]

install:
	pip install -e ".[all]"

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

publish:
	python -m build
	twine upload dist/*

tag:
	git tag v$(VERSION) && git push origin --tags

clean:
	rm -rf dist/ build/ *.egg-info/

lint:
	ruff check blastradius/

format:
	ruff format blastradius/
