.DEFAULT_GOAL := help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-10s %s\n", $$1, $$2}'

setup: ## Create the venv and install dev tools
	uv sync

run: ## Scan a folder: make run ARGS="./code --host root@IP --key K"
	uv run sandbox-scan $(ARGS)

install: ## Install the `sandbox-scan` command globally (editable, runs from any folder)
	uv tool install --editable --force .

uninstall: ## Remove the global `sandbox-scan` command
	uv tool uninstall sandbox-scan

test: ## Run fast tests (no Docker)
	uv run pytest -q -m "not e2e"

e2e: ## Real scan of the attack fixture through Docker (~1 min, needs network)
	uv run pytest -q -m e2e

lint: ## ruff + ty
	uv run ruff check src tests
	uv run ruff format --check src tests
	uvx ty check src tests

.PHONY: help setup run install uninstall test e2e lint
