# IAM Agent — developer tasks.
#
# Everything here goes through .venv/bin/python explicitly rather than relying on
# an activated shell, so the targets behave the same in CI and locally.

PYTHON  ?= .venv/bin/python
PIP     ?= .venv/bin/pip
PYTEST  ?= .venv/bin/python -m pytest
RUFF    ?= .venv/bin/ruff
MYPY    ?= .venv/bin/mypy
CLI     ?= $(PYTHON) -m iam_agent.cli

# Runtime state. Wiped before tests so a run cannot inherit the previous one's
# approvals or estate and quietly pass for the wrong reason.
DATA    := data

.DEFAULT_GOAL := help

## help: list the available targets
.PHONY: help
help:
	@echo "IAM Agent"
	@echo
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## /  make /'
	@echo

## install: create .venv and install the package with dev extras
.PHONY: install
install:
	python3 -m venv .venv
	$(PIP) install --upgrade pip
	$(PIP) install -e ".[dev]"
	@echo
	@echo "Installed. Next: cp .env.example .env && make preflight"

## test: wipe runtime state and run the suite
.PHONY: test
test:
	rm -rf $(DATA)
	$(PYTEST)

## test-verbose: same, with per-test output
.PHONY: test-verbose
test-verbose:
	rm -rf $(DATA)
	$(PYTEST) -v

## lint: ruff over src and tests
.PHONY: lint
lint:
	$(RUFF) check src tests

## lint-fix: ruff, applying safe fixes
.PHONY: lint-fix
lint-fix:
	$(RUFF) check src tests --fix

## typecheck: mypy over the whole package
.PHONY: typecheck
typecheck:
	$(MYPY) src/iam_agent

## check: lint + typecheck + tests. Run this before committing.
.PHONY: check
check: lint typecheck test

## preflight: what is live, what is simulated, what is misconfigured
.PHONY: preflight
preflight:
	$(CLI) preflight

## status: connector health and the current safety posture
.PHONY: status
status:
	$(CLI) status

## demo: a full onboarding cycle against the simulator, approvals included
.PHONY: demo
demo:
	$(PYTHON) scripts/demo.py

## serve: the REST control plane on 0.0.0.0:8000
.PHONY: serve
serve:
	$(CLI) serve --host 0.0.0.0 --port 8000

## mcp: the MCP server on stdio, for Claude Code / Claude Desktop
.PHONY: mcp
mcp:
	$(CLI) mcp

## clean: remove runtime state, caches and build artefacts
.PHONY: clean
clean:
	rm -rf $(DATA) .pytest_cache .mypy_cache .ruff_cache build dist *.egg-info
	find . -type d -name __pycache__ -not -path "./.venv/*" -exec rm -rf {} +

## reset: wipe the simulated estate and start from the seeded default
.PHONY: reset
reset:
	rm -rf $(DATA)
	$(CLI) status >/dev/null
	@echo "Estate reseeded."
