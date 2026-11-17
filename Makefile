.DEFAULT_GOAL := help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-10s %s\n", $$1, $$2}'

setup: ## Create the venv and install dev tools
	uv sync

run: ## Scan a folder: make run ARGS="./code --host root@IP --key K"
	uv run sandbox-scan $(ARGS)

test: ## Run unit tests
	uv run pytest -q

lint: ## ruff + ty
	uv run ruff check src tests
	uv run ruff format --check src tests
	uvx ty check src tests

.PHONY: help setup run test lint
