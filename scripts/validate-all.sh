#!/usr/bin/env bash
# Local quality gate: tests, lint, policy validation and a render dry-run.
# Touches nothing outside a temporary directory; creates no interfaces or firewall rules.
set -euo pipefail

cd "$(dirname "$0")/.."
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "==> unit tests"
uv run pytest

echo "==> lint"
uv run ruff check .
uv run ruff format --check .

echo "==> example policy must pass"
uv run ztnet validate examples/devops-network.yaml --strict

echo "==> insecure policy must be rejected"
if uv run ztnet validate examples/insecure-network.yaml >"$tmp/insecure.txt"; then
  echo "insecure example unexpectedly passed" >&2
  exit 1
fi
grep -q "ZT001" "$tmp/insecure.txt"

echo "==> render dry-run"
uv run ztnet render examples/devops-network.yaml --out "$tmp/out" >/dev/null
if grep -rq "^PrivateKey" "$tmp/out"; then
  echo "rendered output contains a private key line" >&2
  exit 1
fi
echo "rendered $(find "$tmp/out" -type f | wc -l) files"

echo "All local checks passed."
