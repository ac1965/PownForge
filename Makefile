PYTHON ?= python3.11
VENV := .venv

.PHONY: install test lint run docker-build docker-run web-install web-build emacs-test

install:
	test -d $(VENV) || $(PYTHON) -m venv $(VENV)
	$(VENV)/bin/pip install -e ".[dev]"

# Web UI (optional). See docs/web.md for the two-terminal dev workflow:
# `.venv/bin/pownforge web serve` in one, `cd webui && npm run dev` in the
# other. No single `make web-dev` target on purpose, so both processes stay
# visible in their own terminal.
web-install:
	test -d $(VENV) || $(PYTHON) -m venv $(VENV)
	$(VENV)/bin/pip install -e ".[dev,web]"
	cd webui && npm install

web-build:
	cd webui && npm run build

test:
	$(VENV)/bin/pytest

lint:
	$(VENV)/bin/python -m compileall src

run:
	$(VENV)/bin/pownforge --help

# Emacs front-end (optional). See docs/emacs.md. Requires Emacs 27.1+; tests
# run against emacs/tests/fixtures/fake-pownforge, not the real CLI/Python env.
emacs-test:
	emacs --batch -L emacs -L emacs/tests -l ert -l emacs/pownforge.el \
		-l emacs/tests/pownforge-test.el -f ert-run-tests-batch-and-exit

# archlinux:base has no arm64 manifest; force amd64 (QEMU-emulated on Apple
# Silicon hosts) to match compose.yaml's `platform: linux/amd64`.
docker-build:
	docker build --platform linux/amd64 -f docker/Dockerfile.runtime -t pownforge:runtime .

docker-run:
	docker run --rm -it --platform linux/amd64 \
		-v $(PWD)/config:/app/config \
		-v $(PWD)/.pownforge:/app/.pownforge \
		pownforge:runtime
