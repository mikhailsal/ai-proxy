# AI Proxy Service Makefile
# This Makefile provides common development and deployment tasks for AI Proxy and Logs UI

.PHONY: help install install-poetry install-dev
.PHONY: test test-all test-unit test-integration test-watch test-specific test-functional test-functional-gemini test-functional-openrouter test-functional-general
.PHONY: test-ui test-ui-e2e test-ui-unit test-ui-integration test-ui-all
.PHONY: lint lint-fix lint-ui lint-fix-ui type-check type-check-ui pre-commit
.PHONY: clean build dev-compose docker-up docker-down docker-build docker-logs docker-logs-live docker-ps docker-up-ai-proxy docker-up-logs-ui docker-up-traefik docker-restart docker-restart-ai-proxy docker-restart-logs-ui docker-clean
.PHONY: up down restart logs logs-live ps deploy setup-https test-https coverage coverage-ui analyze-code-size check-dependencies health copy-env-example setup-hooks setup ci prod-check
.PHONY: dev dev-up dev-down dev-logs dev-restart dev-build

# Check if Poetry is installed
define check_poetry
	@if ! command -v poetry >/dev/null 2>&1; then \
		echo "❌ Poetry is not installed!"; \
		echo "Please run: make install-poetry"; \
		echo "Or install manually: curl -sSL https://install.python-poetry.org | python3 -"; \
		exit 1; \
	fi
endef

# Auto-detect and export user/group IDs for Docker
define setup_docker_user
	$(eval export HOST_UID := $(shell id -u))
	$(eval export HOST_GID := $(shell id -g))
	@echo "🔧 Using HOST_UID=$(HOST_UID) HOST_GID=$(HOST_GID) for Docker containers"
endef

# Update .env file with current user IDs
define update_env_with_user
	@echo "🔧 Updating .env file with current user information..."
	@if [ ! -f .env ]; then cp .env.example .env; fi
	@if grep -q "^HOST_UID=" .env; then \
		sed -i "s/^HOST_UID=.*/HOST_UID=$(shell id -u)/" .env; \
	else \
		echo "HOST_UID=$(shell id -u)" >> .env; \
	fi
	@if grep -q "^HOST_GID=" .env; then \
		sed -i "s/^HOST_GID=.*/HOST_GID=$(shell id -g)/" .env; \
	else \
		echo "HOST_GID=$(shell id -g)" >> .env; \
	fi
	@echo "✅ Updated .env with HOST_UID=$(shell id -u) HOST_GID=$(shell id -g)"
endef

# Default target
help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# Development setup
install: ## Install dependencies with Poetry
	@echo "Installing dependencies..."
	$(call check_poetry)
	@poetry install
	@echo "Dependencies installed successfully!"

install-poetry: ## Install Poetry using the official installer
	@echo "Installing Poetry using official installer..."
	@curl -sSL https://install.python-poetry.org | python3 -
	@echo "Poetry installed successfully!"
	@echo "Please restart your terminal or run: export PATH=\"$$HOME/.local/bin:$$PATH\""
	@echo "Then run: make install"

install-dev: ## Install development dependencies
	@echo "Installing development dependencies..."
	$(call check_poetry)
	@poetry install --with dev
	@echo "Development dependencies installed successfully!"

# Testing (Docker-only)
test: test-unit test-integration test-ui ## Run all tests (unit, integration, ui-unit) in Docker

test-all: test-unit test-integration test-ui test-ui-e2e test-functional ## Run all tests (unit and integration) in Docker

test-unit: ## Run unit tests in Docker
	@echo "Running unit tests in Docker..."
	@docker compose run --no-TTY --rm -e DOCKER_CONTAINER=true ai-proxy poetry run pytest tests/unit -q --tb=line -n auto

test-integration: ## Run integration tests in Docker
	@echo "Running integration tests in Docker..."
	@docker compose run --no-TTY --rm -e DOCKER_CONTAINER=true ai-proxy sh -c "if [ -n \"\$$(find tests/integration -name 'test_*.py' -type f 2>/dev/null)\" ]; then poetry run pytest tests/integration -q --tb=line; else echo 'No integration tests found, skipping...'; fi"

test-functional: ## Run all functional tests with real API keys (disabled by default)
	@echo "⚠️  WARNING: Functional tests use real API keys and may incur costs!"
	@echo "Running all functional tests with Docker Compose..."
	@TEST_PATH=tests/functional docker compose -f docker-compose.test.yml up --build --abort-on-container-exit --remove-orphans || \
	(echo "❌ Functional tests FAILED!" && docker compose -f docker-compose.test.yml logs pytest && docker compose -f docker-compose.test.yml down -v && exit 1)
	@echo "✅ Functional tests PASSED!"
	@docker compose -f docker-compose.test.yml down -v > /dev/null 2>&1

test-functional-gemini: ## Run only Gemini functional tests
	@echo "⚠️  WARNING: Gemini functional tests use real API keys and may incur costs!"
	@echo "Running Gemini functional tests..."
	@TEST_PATH=tests/functional/test_gemini.py docker compose -f docker-compose.test.yml up --build --abort-on-container-exit --remove-orphans || \
	(echo "❌ Gemini functional tests FAILED!" && docker compose -f docker-compose.test.yml logs pytest && docker compose -f docker-compose.test.yml down -v && exit 1)
	@echo "✅ Gemini functional tests PASSED!"
	@docker compose -f docker-compose.test.yml down -v > /dev/null 2>&1

test-functional-openrouter: ## Run only OpenRouter functional tests
	@echo "⚠️  WARNING: OpenRouter functional tests use real API keys and may incur costs!"
	@echo "Running OpenRouter functional tests..."
	@TEST_PATH=tests/functional/test_openrouter.py docker compose -f docker-compose.test.yml up --build --abort-on-container-exit --remove-orphans || \
	(echo "❌ OpenRouter functional tests FAILED!" && docker compose -f docker-compose.test.yml logs pytest && docker compose -f docker-compose.test.yml down -v && exit 1)
	@echo "✅ OpenRouter functional tests PASSED!"
	@docker compose -f docker-compose.test.yml down -v > /dev/null 2>&1

test-functional-general: ## Run only general functional tests (no external API costs)
	@echo "Running general functional tests (no external API costs)..."
	@TEST_PATH=tests/functional/test_general.py docker compose -f docker-compose.test.yml up --build --abort-on-container-exit --remove-orphans || \
	(echo "❌ General functional tests FAILED!" && docker compose -f docker-compose.test.yml logs pytest && docker compose -f docker-compose.test.yml down -v && exit 1)
	@echo "✅ General functional tests PASSED!"
	@docker compose -f docker-compose.test.yml down -v > /dev/null 2>&1

test-watch: ## Run tests in watch mode in Docker
	@echo "Running tests in watch mode in Docker..."
	@docker compose run --rm -e DOCKER_CONTAINER=true ai-proxy poetry run pytest tests/ -q --tb=line -f

# UI testing
test-ui: ## Run UI unit tests (Dockerized Node)
	@echo "Running UI unit tests in Docker (Node 20)..."
	@docker run --rm -v $(PWD)/ui:/app -w /app node:20 bash -lc "npm ci --no-audit --fund=false --loglevel=error && npm run test --silent"

# New frontend quality targets
lint-ui: ## Run frontend linting (Dockerized)
	@echo "Running frontend linting in Docker (Node 20)..."
	@docker run --rm -v $(PWD)/ui:/app -w /app node:20 bash -lc "npm ci --no-audit --fund=false --loglevel=error && npm run lint"

lint-fix-ui: ## Fix frontend linting issues (Dockerized)
	@echo "Fixing frontend linting in Docker (Node 20)..."
	@docker run --rm -v $(PWD)/ui:/app -w /app node:20 bash -lc "npm ci --no-audit --fund=false --loglevel=error && npm run lint:fix"

type-check-ui: ## Run frontend type checking (Dockerized)
	@echo "Running frontend type checking in Docker (Node 20)..."
	@docker run --rm -v $(PWD)/ui:/app -w /app node:20 bash -lc "npm ci --no-audit --fund=false --loglevel=error && npm run typecheck"

coverage-ui: ## Run frontend tests with coverage (Dockerized)
	@echo "Running frontend coverage in Docker (Node 20)..."
	@docker run --rm --network host -v $(PWD)/ui:/app -w /app node:20 bash -lc "npm ci --no-audit --fund=false --loglevel=error && npm run coverage"

test-ui-e2e: ## Run UI E2E tests with Playwright (Dockerized Node)
	@echo "Running UI E2E tests in Docker (Node 20 + Playwright)..."
	@docker run --rm \
		-v $(PWD)/ui:/app \
		-w /app \
		--ipc=host \
		mcr.microsoft.com/playwright:v1.55.0-jammy bash -lc "npm ci --no-audit --fund=false --loglevel=error && UI_NO_WEBSERVER= npx playwright test --reporter=list"

# AI Proxy UI (Python API) testing
test-ui-unit: ## Run unit tests for AI Proxy UI (Python API)
	@echo "Running AI Proxy UI unit tests..."
	@if [ -d "tests/unit" ] && [ -n "$$(find tests/unit -name '*ui*' -o -name '*logs_ui*' -type f 2>/dev/null)" ]; then \
		docker compose run --rm -e DOCKER_CONTAINER=true ai-proxy poetry run pytest tests/unit -k "ui or logs_ui" -q --tb=line; \
	else \
		echo "No AI Proxy UI unit tests found, skipping..."; \
	fi

test-ui-integration: ## Run integration tests for AI Proxy UI (Python API)
	@echo "Running AI Proxy UI integration tests..."
	@if [ -d "tests/integration" ] && [ -n "$$(find tests/integration -name '*ui*' -o -name '*logs_ui*' -type f 2>/dev/null)" ]; then \
		docker compose run --rm -e DOCKER_CONTAINER=true ai-proxy poetry run pytest tests/integration -k "ui or logs_ui" -q --tb=line; \
	else \
		echo "No AI Proxy UI integration tests found, skipping..."; \
	fi

test-ui-all: test-ui-unit test-ui-integration ## Run all AI Proxy UI tests
	@echo "All AI Proxy UI tests completed!"

coverage: ## Run tests with coverage report in Docker (includes scripts/)
	@echo "Running tests with coverage in Docker..."
	@docker compose run --rm -e DOCKER_CONTAINER=true -e COVERAGE_FILE=/app/logs/.coverage ai-proxy \
		poetry run pytest tests/ --tb=line \
			--cov=ai_proxy --cov=ai_proxy_ui --cov=scripts \
			--cov-report=term-missing --cov-report=html:/app/logs/coverage-html \
		|| { echo "Coverage reporting requires pytest-cov"; exit 1; }

test-specific: ## Run specific test file or function in Docker (usage: make test-specific TEST=path/to/test.py)
	@echo "Running specific test in Docker..."
	@if [ -z "$(TEST)" ]; then \
		echo "Usage: make test-specific TEST=path/to/test.py"; \
		echo "       make test-specific TEST=path/to/test.py::test_function"; \
		exit 1; \
	fi
	@docker compose run --rm -e DOCKER_CONTAINER=true ai-proxy poetry run pytest $(TEST) -q --tb=line

# Code quality
lint: ## Run linting checks
	@echo "Running linting checks..."
	$(call check_poetry)
	@poetry run ruff check ai_proxy/ ai_proxy_ui/ tests/
	@poetry run ruff format --check ai_proxy/ ai_proxy_ui/ tests/

lint-fix: ## Format code and fix linting errors with ruff
	@echo "Formatting and fixing code..."
	$(call check_poetry)
	@poetry run ruff format ai_proxy/ ai_proxy_ui/ tests/
	@poetry run ruff check --fix ai_proxy/ ai_proxy_ui/ tests/

type-check: ## Run type checking with mypy
	@echo "Running type checks..."
	$(call check_poetry)
	@poetry run mypy ai_proxy/ ai_proxy_ui/ scripts/

pre-commit: ## Run pre-commit hooks
	@echo "Running pre-commit hooks..."
	$(call check_poetry)
	@poetry run pre-commit run --all-files

analyze-code-size: ## Analyze code size and provide refactoring recommendations
	@echo "Analyzing code size..."
	@python scripts/analyze_code_size.py

check-dependencies: ## Check module dependencies and detect circular imports
	@echo "Checking module dependencies..."
	@python scripts/check_module_dependencies.py

# Docker operations
docker-up: ## Start all services with Docker Compose
	@echo "Starting all services with Docker Compose..."
	$(call setup_docker_user)
	$(call update_env_with_user)
	@docker compose up -d
	@echo "Waiting for services to start..."
	@sleep 5
	@docker ps

docker-down: ## Stop all services with Docker Compose
	@echo "Stopping all services with Docker Compose..."
	@docker compose down

docker-build: ## Build all services with Docker Compose
	@echo "Building all services with Docker Compose..."
	$(call setup_docker_user)
	$(call update_env_with_user)
	@docker compose build

docker-logs: ## View logs from all services (non-interactive)
	@echo "Viewing logs from all services..."
	@docker compose logs

docker-logs-live: ## View logs from all services (interactive/live mode)
	@echo "Viewing logs from all services (live mode)..."
	@docker compose logs -f

docker-ps: ## List all running services
	@echo "Listing all running services..."
	@docker compose ps

# Individual Docker service management
docker-up-ai-proxy: ## Start only the AI Proxy service
	@echo "Starting AI Proxy service..."
	@docker compose up -d ai-proxy

docker-up-logs-ui: ## Start only the Logs UI services (API and Web)
	@echo "Starting Logs UI services..."
	@docker compose up -d logs-ui-api logs-ui-web

docker-up-traefik: ## Start only the Traefik reverse proxy
	@echo "Starting Traefik reverse proxy..."
	@docker compose up -d traefik

docker-restart: ## Full restart of all services (down and up)
	@echo "Restarting all services..."
	$(call setup_docker_user)
	$(call update_env_with_user)
	@make docker-down
	@make docker-up

docker-restart-ai-proxy: ## Restart only the AI Proxy service
	@echo "Restarting AI Proxy service..."
	@docker compose restart ai-proxy

docker-restart-logs-ui: ## Restart only the Logs UI services
	@echo "Restarting Logs UI services..."
	@docker compose restart logs-ui-api logs-ui-web

# Docker cleanup
docker-clean: ## Clean Docker resources and system
	@echo "Cleaning Docker resources..."
	@docker compose down -v --rmi all 2>/dev/null || true
	@docker system prune -f

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
	@find . \( -path "./.venv" -o -path "./venv" \) -prune -o -type f -name "*.pyc" -exec rm -v -f {} +
	@find . \( -path "./.venv" -o -path "./venv" \) -prune -o -type d -name "__pycache__" -exec rm -v -rf {} +
	@find . \( -path "./.venv" -o -path "./venv" \) -prune -o -type d -name "*.egg-info" -exec rm -v -rf {} +
	@rm -rfv ./.pytest_cache/
	@rm -rfv ./.coverage
	@rm -rfv ./htmlcov/
	@rm -rfv ./logs/.coverage*
	@rm -rfv ./logs/coverage-html/
	@rm -rfv ./dist/
	@rm -rfv ./build/
	@echo "Cleaning ai_proxy_ui temporary files..."
	@find ./ai_proxy_ui \( -type f -name "*.pyc" -o -name "*.pyo" \) -exec rm -v -f {} + 2>/dev/null || true
	@find ./ai_proxy_ui -type d -name "__pycache__" -exec rm -v -rf {} + 2>/dev/null || true

health: ## Check all services health (AI Proxy, Logs UI API, Traefik)
	@echo "Checking all services health..."
	@echo "AI Proxy: $$(curl -s --max-time 5 http://localhost:8123/health 2>/dev/null | jq -r '.status // "unavailable"' 2>/dev/null || echo "unavailable")"
	@echo "Logs UI API: $$(curl -s --max-time 5 http://localhost:8124/ui/health 2>/dev/null | jq -r '.status // "unavailable"' 2>/dev/null || echo "unavailable")"
	@echo "Traefik: $$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 http://localhost:8080/ | grep -q "^[0-9][0-9][0-9]$$" && echo "ok" || echo "unavailable")"

# Environment setup
copy-env-example: ## Copy .env.example to .env (only if .env doesn't exist)
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
	$(call check_poetry)
	@poetry run pre-commit install

# All-in-one commands
setup: install setup-hooks copy-env-example ## Complete development setup
	@echo "Development setup complete!"
	@echo "Please edit .env with your configuration before running the application"

# Quick service management
up: docker-up ## Alias for docker-up
down: docker-down ## Alias for docker-down
restart: docker-restart ## Alias for docker-restart
build: docker-build ## Alias for docker-build
logs: docker-logs ## Alias for docker-logs
logs-live: docker-logs-live ## Alias for docker-logs-live (interactive mode)
ps: docker-ps ## Alias for docker-ps

ci: lint test test-ui-all coverage lint-ui type-check-ui coverage-ui ## Run all CI checks including frontend
	@echo "All CI checks completed!"

# Production readiness check
prod-check: lint type-check test test-ui-all coverage ## Check if ready for production in Docker
	@echo "Production readiness check completed!"

# Development environment (Logs UI with hot reload)
dev: dev-build dev-up ## Build and start development environment with hot reload
	@echo "🚀 Development environment is starting..."
	@echo "📝 Logs UI (web): http://localhost:5174 (dev) or https://logs.localhost:51999"
	@echo "📝 Logs UI (API): http://localhost:8124 or https://logs-api.localhost:51999"
	@echo "📝 AI Proxy: http://localhost:8123 or https://ai-proxy.localhost:51999"
	@echo ""
	@echo "⚡ Hot reload is enabled for both frontend and backend!"
	@echo "   - Edit files in ui/src/ → instant browser reload"
	@echo "   - Edit files in ai_proxy_ui/ → automatic FastAPI reload"
	@echo ""
	@echo "📚 Run 'make dev-logs' to follow logs"

dev-up: ## Start development environment
	@echo "Starting development environment..."
	$(call setup_docker_user)
	$(call update_env_with_user)
	# Start standalone development compose (dev-only, does not include production services)
	@docker compose -f docker-compose.dev.yml up -d
	@sleep 3
	@docker compose -f docker-compose.dev.yml ps

dev-down: ## Stop development environment
	@echo "Stopping development environment..."
	@docker compose -f docker-compose.dev.yml down

dev-build: ## Build development environment
	@echo "Building development environment..."
	$(call setup_docker_user)
	$(call update_env_with_user)
	@docker compose -f docker-compose.dev.yml build --no-cache logs-ui-web

dev-restart: ## Restart development environment
	@echo "Restarting development environment..."
	@docker compose -f docker-compose.dev.yml restart

dev-logs: ## View logs from development environment
	@echo "Viewing logs from development environment..."
	@docker compose -f docker-compose.dev.yml logs -f logs-ui-web logs-ui-api
