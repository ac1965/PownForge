PYTHON ?= python3.11
VENV := .venv

.PHONY: install test lint run docker-build docker-run

install:
	test -d $(VENV) || $(PYTHON) -m venv $(VENV)
	$(VENV)/bin/pip install -e ".[dev]"

test:
	$(VENV)/bin/pytest

lint:
	$(VENV)/bin/python -m compileall src

run:
	$(VENV)/bin/pownforge --help

docker-build:
	docker build -f docker/Dockerfile.runtime -t pownforge:runtime .

docker-run:
	docker run --rm -it \
		-v $(PWD)/config:/app/config \
		-v $(PWD)/.pownforge:/app/.pownforge \
		pownforge:runtime
