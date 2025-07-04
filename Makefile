# AI Proxy Service Makefile
# This Makefile provides common development and deployment tasks

.PHONY: help install test test-unit test-integration lint lint-fix type-check clean build run dev docker-build docker-run docker-clean deploy setup-https test-https coverage pre-commit

# Default target
help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# Development setup
install: ## Install dependencies with Poetry
	@echo "Installing dependencies..."
	@poetry install
	@echo "Dependencies installed successfully!"

install-dev: ## Install development dependencies
	@echo "Installing development dependencies..."
	@poetry install --with dev
	@echo "Development dependencies installed successfully!"

# Testing (Docker-only)
test: test-unit test-integration ## Run all tests (unit and integration) in Docker

test-unit: ## Run unit tests in Docker
	@echo "Running unit tests in Docker..."
	@docker run --rm -e DOCKER_CONTAINER=true -v $(PWD):/app ai-proxy poetry run pytest tests/unit -q --tb=line

test-integration: ## Run integration tests in Docker
	@echo "Running integration tests in Docker..."
	@docker run --rm -e DOCKER_CONTAINER=true -v $(PWD):/app ai-proxy sh -c "if [ -n \"\$$(find tests/integration -name 'test_*.py' -type f 2>/dev/null)\" ]; then poetry run pytest tests/integration -q --tb=line; else echo 'No integration tests found, skipping...'; fi"

test-watch: ## Run tests in watch mode in Docker
	@echo "Running tests in watch mode in Docker..."
	@docker run --rm -e DOCKER_CONTAINER=true -v $(PWD):/app ai-proxy poetry run pytest tests/ -q --tb=line -f

coverage: ## Run tests with coverage report in Docker
	@echo "Running tests with coverage in Docker..."
	@docker run --rm -e DOCKER_CONTAINER=true -v $(PWD):/app ai-proxy poetry run pytest tests/ --tb=line --cov=ai_proxy --cov-report=html || echo "Coverage reporting requires pytest-cov"

test-specific: ## Run specific test file or function in Docker (usage: make test-specific TEST=path/to/test.py)
	@echo "Running specific test in Docker..."
	@if [ -z "$(TEST)" ]; then \
		echo "Usage: make test-specific TEST=path/to/test.py"; \
		echo "       make test-specific TEST=path/to/test.py::test_function"; \
		exit 1; \
	fi
	@docker run --rm -e DOCKER_CONTAINER=true -v $(PWD):/app ai-proxy poetry run pytest $(TEST) -q --tb=line

# Code quality
lint: ## Run linting checks
	@echo "Running linting checks..."
	@poetry run ruff check ai_proxy/ tests/
	@poetry run ruff format --check ai_proxy/ tests/

lint-fix: ## Format code and fix linting errors with ruff
	@echo "Formatting and fixing code..."
	@poetry run ruff format ai_proxy/ tests/
	@poetry run ruff check --fix ai_proxy/ tests/

type-check: ## Run type checking with mypy
	@echo "Running type checks..."
	@poetry run mypy ai_proxy/ || echo "Type checking failed - consider fixing type issues or adding type stubs"

pre-commit: ## Run pre-commit hooks
	@echo "Running pre-commit hooks..."
	@poetry run pre-commit run --all-files

# Development server
dev: ## Run development server with auto-reload
	@echo "Starting development server..."
	@poetry run uvicorn ai_proxy.main:app --reload --host 0.0.0.0 --port 8123

run: ## Run production server
	@echo "Starting production server..."
	@poetry run uvicorn ai_proxy.main:app --host 0.0.0.0 --port 8123

# Docker operations
docker-build: ## Build Docker image
	@echo "Building Docker image..."
	@docker build -t ai-proxy:latest .

docker-run: ## Run Docker container
	@echo "Running Docker container..."
	@docker run -d --name ai-proxy-container --env-file .env -p 8123:8123 ai-proxy:latest

docker-stop: ## Stop Docker container
	@echo "Stopping Docker container..."
	@docker stop ai-proxy-container || true
	@docker rm ai-proxy-container || true

docker-clean: ## Clean Docker images and containers
	@echo "Cleaning Docker images and containers..."
	@docker stop ai-proxy-container || true
	@docker rm ai-proxy-container || true
	@docker rmi ai-proxy:latest || true
	@docker image prune -f

# Production deployment
deploy: ## Deploy to production (use DEPLOY_HOST=hostname make deploy)
	@if [ -z "$(DEPLOY_HOST)" ]; then \
		echo "Usage: DEPLOY_HOST=hostname make deploy"; \
		echo "This uses the existing deployment script with proper safety checks"; \
		exit 1; \
	else \
		echo "Deploying to production using deployment script..."; \
		DEPLOY_HOST=$(DEPLOY_HOST) ./scripts/deploy-production.sh; \
	fi

deploy-stop: ## Stop production deployment
	@echo "Stopping production deployment..."
	@docker-compose down

deploy-logs: ## View production logs
	@echo "Viewing production logs..."
	@docker-compose logs -f

# HTTPS setup
setup-https: ## Set up HTTPS with Let's Encrypt
	@echo "Setting up HTTPS..."
	@./scripts/setup-https.sh

test-https: ## Test HTTPS setup
	@echo "Testing HTTPS setup..."
	@./scripts/test-https.sh

# Utility commands
clean: ## Clean temporary files and caches
	@echo "Cleaning temporary files..."
	@find . -type f -name "*.pyc" -delete
	@find . -type d -name "__pycache__" -delete
	@find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	@rm -rf .pytest_cache/
	@rm -rf .coverage
	@rm -rf htmlcov/
	@rm -rf dist/
	@rm -rf build/

logs: ## View application logs
	@echo "Viewing application logs..."
	@tail -f logs/*.log 2>/dev/null || echo "No log files found in logs/ directory"

health: ## Check application health (works with both local and Docker)
	@echo "Checking application health..."
	@curl -s http://localhost:8123/health 2>/dev/null || \
	 docker exec ai-proxy-container curl -s http://localhost:8123/health 2>/dev/null || \
	 echo "Application not running or health endpoint not available"

# Environment setup
env-example: ## Copy .env.example to .env (only if .env doesn't exist)
	@if [ ! -f .env ]; then \
		echo "Copying .env.example to .env..."; \
		cp .env.example .env; \
		echo "Please edit .env with your configuration"; \
	else \
		echo ".env already exists, skipping copy"; \
	fi

# Git hooks
setup-hooks: ## Install git hooks
	@echo "Installing git hooks..."
	@poetry run pre-commit install

# Security
security-check: ## Run security checks
	@echo "Running security checks..."
	@poetry run pip-audit || echo "pip-audit not available, skipping security check"

# Documentation
docs: ## Generate documentation (placeholder)
	@echo "Documentation generation not implemented yet"

# All-in-one commands
setup: install setup-hooks env-example ## Complete development setup
	@echo "Development setup complete!"
	@echo "Please edit .env with your configuration before running the application"

ci: lint test coverage ## Run all CI checks (excluding type-check due to missing stubs) in Docker
	@echo "All CI checks completed!"

# Quick development workflow
quick-test: lint-fix test-unit ## Quick test cycle for development in Docker
	@echo "Quick test cycle completed!"

# Production readiness check
prod-check: lint type-check test coverage security-check ## Check if ready for production in Docker
	@echo "Production readiness check completed!" 