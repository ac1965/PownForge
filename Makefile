.PHONY: install test lint run docker-build docker-run

install:
	pip install -e ".[dev]"

test:
	pytest

lint:
	python -m compileall src

run:
	pownforge --help

docker-build:
	docker build -f docker/Dockerfile.runtime -t pownforge:runtime .

docker-run:
	docker run --rm -it \
		-v $(PWD)/config:/app/config \
		-v $(PWD)/.pownforge:/app/.pownforge \
		pownforge:runtime
