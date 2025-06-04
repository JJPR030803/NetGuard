.PHONY: help install dev-install test lint format type-check security clean build run docker-build docker-run

# Colors for terminal output
BLUE := \033[34m
GREEN := \033[32m
YELLOW := \033[33m
RED := \033[31m
NC := \033[0m # No Color

help: ## Show this help message
	@echo "$(BLUE)Network Security Suite - Development Commands$(NC)"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(GREEN)%-20s$(NC) %s\n", $$1, $$2}'

install: ## Install production dependencies
	@echo "$(BLUE)Installing production dependencies...$(NC)"
	poetry install --only=main

dev-install: ## Install all dependencies including development
	@echo "$(BLUE)Installing all dependencies...$(NC)"
	poetry install
	poetry run pre-commit install

test: ## Run all tests
	@echo "$(BLUE)Running tests...$(NC)"
	poetry run pytest tests/ -v --cov=src --cov-report=html --cov-report=term-missing

test-unit: ## Run unit tests only
	@echo "$(BLUE)Running unit tests...$(NC)"
	poetry run pytest tests/unit/ -v

test-integration: ## Run integration tests only
	@echo "$(BLUE)Running integration tests...$(NC)"
	poetry run pytest tests/integration/ -v

lint: ## Run all linting tools
	@echo "$(BLUE)Running linting tools...$(NC)"
	poetry run ruff check src/
	poetry run pylint src/

enforce-lint:
	@echo "$(BLUE) Enforcing linting tools...$(NC)"
	poetry run ruff check --fix src/
	poetry run pylint src/

enforce-format:
	@echo "$(BLUE)Enforcing format...$(NC)"
	poetry run ruff format src/ tests/
	poetry run black src/ tests/
	poetry run isort src/ tests/
format: ## Format code with ruff, black and isort
	@echo "$(BLUE)Formatting code...$(NC)"
	poetry run ruff format src/ tests/
	poetry run black src/ tests/
	poetry run isort src/ tests/

type-check: ## Run type checking with mypy
	@echo "$(BLUE)Running type checks...$(NC)"
	poetry run mypy src/

security: ## Run security checks
	@echo "$(BLUE)Running security checks...$(NC)"
	poetry run bandit -r src/
	poetry run pip freeze | poetry run safety check --stdin

quality: format lint type-check security ## Run all code quality checks

enforce-quality: enforce-format enforce-lint type-check security

pre-commit: ## Run pre-commit hooks on all files
	@echo "$(BLUE)Running pre-commit hooks...$(NC)"
	poetry run pre-commit run --all-files

clean: ## Clean up cache and temporary files
	@echo "$(BLUE)Cleaning up...$(NC)"
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	rm -rf .coverage htmlcov/ .pytest_cache/ .mypy_cache/
	rm -rf build/ dist/

build: ## Build the package
	@echo "$(BLUE)Building package...$(NC)"
	poetry build

run: ## Run the application locally
	@echo "$(BLUE)Starting application...$(NC)"
	poetry run uvicorn src.network_security_suite.main:app --reload --host 0.0.0.0 --port 8000

run-prod: ## Run the application in production mode
	@echo "$(BLUE)Starting application in production mode...$(NC)"
	poetry run uvicorn src.network_security_suite.main:app --host 0.0.0.0 --port 8000

docker-build: ## Build Docker image
	@echo "$(BLUE)Building Docker image...$(NC)"
	docker build -t network-security-suite:latest .

docker-build-dev: ## Build Docker image for development
	@echo "$(BLUE)Building Docker development image...$(NC)"
	docker build --target development -t network-security-suite:dev .

docker-run: ## Run application in Docker container
	@echo "$(BLUE)Running Docker container...$(NC)"
	docker run -p 8000:8000 network-security-suite:latest

docker-dev: ## Run development environment with docker-compose
	@echo "$(BLUE)Starting development environment...$(NC)"
	docker-compose up --build

docker-down: ## Stop development environment
	@echo "$(BLUE)Stopping development environment...$(NC)"
	docker-compose down

docker-logs: ## Show docker-compose logs
	@echo "$(BLUE)Showing logs...$(NC)"
	docker-compose logs -f

init-db: ## Initialize database
	@echo "$(BLUE)Initializing database...$(NC)"
	poetry run alembic upgrade head

migrate: ## Create new database migration
	@echo "$(BLUE)Creating new migration...$(NC)"
	@echo "$(YELLOW)Usage: make migrate msg='migration message'$(NC)"
	poetry run alembic revision --autogenerate -m "$(msg)"

upgrade-db: ## Upgrade database to latest migration
	@echo "$(BLUE)Upgrading database...$(NC)"
	poetry run alembic upgrade head

downgrade-db: ## Downgrade database by one migration
	@echo "$(BLUE)Downgrading database...$(NC)"
	poetry run alembic downgrade -1

docs-serve: ## Server documentation locally
	@echo "$(BLUE)Serving documentation...$(NC)"
	poetry run mkdocs serve

docs-build: ## Build documentation
	@echo "$(BLUE)Building documentation...$(NC)"
	poetry run mkdocs build

setup: dev-install pre-commit ## Complete project setup
	@echo "$(GREEN)Project setup complete!$(NC)"
	@echo ""
	@echo "$(YELLOW)Next steps:$(NC)"
	@echo "1. Run '$(GREEN)make run$(NC)' to start the development server"
	@echo "2. Run '$(GREEN)make test$(NC)' to run tests"
	@echo "3. Run '$(GREEN)make docker-dev$(NC)' to start with Docker"

# Development workflow shortcuts
dev: format lint type-check test ## Complete development workflow

ci: quality test ## Simulate CI pipeline locally

quick-test: ## Quick test run (no coverage)
	@echo "$(BLUE)Running quick tests...$(NC)"
	poetry run pytest tests/ -v -x

watch-test: ## Run tests in watch mode
	@echo "$(BLUE)Running tests in watch mode...$(NC)"
	poetry run pytest-watch tests/
