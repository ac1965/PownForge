PYTHON ?= python3.11
VENV := .venv

.PHONY: install test test-all lint run clean docker-build docker-run web-install web-build emacs-test

install:
	test -d $(VENV) || $(PYTHON) -m venv $(VENV)
	$(VENV)/bin/pip install -e ".[dev]"

# Web UI (optional). See docs/handbook.md §8 for the two-terminal dev workflow:
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

# Runs the Python suite plus the optional webui/Emacs front-ends together.
# Kept separate from `test` (which CI and contributors without Node/Emacs
# installed still need to work) -- use this locally when you have `npm`
# (webui/node_modules present) and `emacs` on PATH.
test-all: test web-build emacs-test

lint:
	$(VENV)/bin/python -m compileall src

run:
	$(VENV)/bin/pownforge --help

# Removes generated/cache files only -- never .venv, webui/node_modules, or
# .pownforge/ (real scan evidence), since those are either expensive to
# rebuild or actual data, not build output.
clean:
	find . -name '__pycache__' -not -path './.venv/*' -not -path './webui/node_modules/*' -exec rm -rf {} +
	rm -rf *.egg-info src/*.egg-info .pytest_cache dist build
	rm -rf webui/dist webui/.vite

# Emacs front-end (optional). See docs/handbook.md §9. Requires Emacs 27.1+; tests
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
