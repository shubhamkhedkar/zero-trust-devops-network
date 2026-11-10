.PHONY: install test lint format audit validate render decide serve clean

POLICY ?= examples/devops-network.yaml

install:
	uv sync --frozen

test:
	uv run pytest

lint:
	uv run ruff check .
	uv run ruff format --check .
	shellcheck scripts/*.sh

format:
	uv run ruff format .

audit:
	uv export --frozen --format requirements-txt --no-hashes > /tmp/ztnet-reqs.txt
	uvx pip-audit -r /tmp/ztnet-reqs.txt

validate:
	uv run ztnet validate $(POLICY)

render:
	uv run ztnet render $(POLICY) --out out/

decide:
	uv run ztnet decide $(POLICY) --src gha-runner-01 --dst k8s-prod-api --protocol tcp --port 6443

serve:
	uv run ztnet serve --policy $(POLICY) --port 8080

clean:
	rm -rf .venv .pytest_cache .ruff_cache out dist
