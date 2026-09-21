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

# archlinux:base has no arm64 manifest; force amd64 (QEMU-emulated on Apple
# Silicon hosts) to match compose.yaml's `platform: linux/amd64`.
docker-build:
	docker build --platform linux/amd64 -f docker/Dockerfile.runtime -t pownforge:runtime .

docker-run:
	docker run --rm -it --platform linux/amd64 \
		-v $(PWD)/config:/app/config \
		-v $(PWD)/.pownforge:/app/.pownforge \
		pownforge:runtime
