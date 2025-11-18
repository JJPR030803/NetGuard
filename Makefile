.PHONY: help install format lint type-check test clean docs-build docs-serve pre-commit check

# Colors for terminal output
BLUE := \033[34m
GREEN := \033[32m
YELLOW := \033[33m
NC := \033[0m # No Color

help: ## Show this help message
	@echo "$(BLUE)NetGuard - Development Commands$(NC)"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(GREEN)%-20s$(NC) %s\n", $$1, $$2}'

install: ## Install all dependencies (including dev tools)
	@echo "$(BLUE)Installing dependencies...$(NC)"
	uv sync --all-extras
	uv run pre-commit install

# Code Quality Commands

format: ## Format code with black and isort
	@echo "$(BLUE)Formatting code...$(NC)"
	uv run black src/ tests/
	uv run isort src/ tests/

lint: ## Run linting (ruff + pylint)
	@echo "$(BLUE)Running linters...$(NC)"
	uv run ruff check src/ tests/
	uv run pylint src/

lint-fix: ## Run linting with auto-fix
	@echo "$(BLUE)Running linters with auto-fix...$(NC)"
	uv run ruff check --fix src/ tests/

type-check: ## Run type checking with mypy
	@echo "$(BLUE)Running type checks...$(NC)"
	uv run mypy src/

check: format lint type-check ## Run all code quality checks

# Testing Commands

test: ## Run tests with coverage
	@echo "$(BLUE)Running tests...$(NC)"
	uv run pytest tests/ -v --cov=src --cov-report=html --cov-report=term-missing

test-quick: ## Run tests without coverage
	@echo "$(BLUE)Running quick tests...$(NC)"
	uv run pytest tests/ -v -x

# Documentation Commands

docs-serve: ## Serve documentation locally (http://127.0.0.1:8000)
	@echo "$(BLUE)Serving documentation...$(NC)"
	uv run mkdocs serve

docs-build: ## Build documentation to site/
	@echo "$(BLUE)Building documentation...$(NC)"
	uv run mkdocs build --clean

docs-deploy: ## Deploy documentation to GitHub Pages
	@echo "$(BLUE)Deploying documentation...$(NC)"
	uv run mkdocs gh-deploy

# Pre-commit

pre-commit: ## Run pre-commit hooks on all files
	@echo "$(BLUE)Running pre-commit hooks...$(NC)"
	uv run pre-commit run --all-files

# Cleanup

clean: ## Clean cache and temporary files
	@echo "$(BLUE)Cleaning up...$(NC)"
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	find . -type d -name ".mypy_cache" -exec rm -rf {} +
	find . -type d -name ".ruff_cache" -exec rm -rf {} +
	rm -rf .coverage htmlcov/ build/ dist/ site/
