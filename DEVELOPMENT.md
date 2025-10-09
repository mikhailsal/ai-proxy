# Development Guide

This guide offers instructions for developers to contribute to the AI Proxy service, run it locally, or understand its internals. For user documentation, see `README.md`.

## Prerequisites

*   Python 3.10+
*   [Poetry](https://python-poetry.org/) for dependency management.
*   Docker and Docker Compose.
*   Git and make

## Quick start

```bash
# Install dependencies
make install-dev

# Copy example .env and install hooks
make setup

# Start development environment
make dev
```
## Git hooks (pre-commit)

To ensure code quality gates run locally the repository uses `pre-commit` hooks defined in `.pre-commit-config.yaml`.

- **Install and enable hooks (recommended)**

    ```bash
    # Install development dependencies and hooks via Makefile
    make install-dev   # or: poetry install --with dev
    make setup-hooks    # runs: poetry run pre-commit install

    # Alternatively, install hooks directly
    poetry run pre-commit install
    ```

- **Run hooks manually (check everything)**

    ```bash
    poetry run pre-commit run --all-files
    # or via Makefile
    make pre-commit
    ```

- **Required tools for full hook execution**

  - `poetry` (required) — local hooks like `mypy-poetry` run `poetry run ...`
  - `docker` and `docker compose` — required by the `run-unit-tests` hook which calls `make test-unit` (tests run in Docker)
  - `make` — used by Makefile targets invoked by hooks
  - `node` + `npm` — only if you prefer running frontend hooks locally without Docker; otherwise frontend hooks invoke Docker via `make lint-ui` / `make type-check-ui`
  - Python 3.10+ — to run local scripts and pre-commit system hooks

- **Notes**
  - Some hooks are configured as `language: system` and expect the above tools to be available on your PATH; the Makefile targets usually prefer Docker to keep environments reproducible.
  - Use `make setup` to perform a one-shot setup that installs deps, hooks, and copies the example `.env`:

    ```bash
    make setup
    ```

## Development Environment with Hot Reload 🚀

**For Logs UI development with instant hot reload:**

```bash
# One command to start everything
make dev
```

This starts:
- ✅ **Logs UI (React + Vite)** with Hot Module Replacement (HMR)
- ✅ **Logs UI API (FastAPI)** with auto-reload on code changes
- ✅ **AI Proxy** and **Traefik** (full production-like environment)

**Access points:**
- Logs UI (frontend): http://localhost:5174
- Logs UI API: http://localhost:8124
- AI Proxy API: http://localhost:8123

**Development workflow:**
```bash
# Start development environment
make dev

# View logs from frontend and backend
make dev-logs

# Restart, stop if needed
make dev-restart
make dev-down
```

**What gets hot-reloaded:**
- Edit `ui/src/**/*.tsx` → **Instant browser reload** ⚡
- Edit `ai_proxy_ui/**/*.py` → **FastAPI auto-reloads** 🔄
- Edit `ai_proxy/**/*.py` → **AI Proxy auto-reloads** 🔄

**Note:** Development mode uses `docker-compose.dev.yml`

---

## Local Development (HTTP)

1.  **Install dependencies:**
    ```bash
    poetry install
    ```

2.  **Set up environment variables:**
    Create a `.env` file from the example:
    ```bash
    cp .env.example .env
    ```
    Edit `.env` with your configuration. For local development, you mainly need API keys.
    ```bash
    # Example .env for local development
    API_KEYS=your-secret-key
    OPENROUTER_API_KEY=your-openrouter-key
    GEMINI_API_KEY=your-gemini-key
    ```

3.  **Run the service:**
    ```bash
    poetry run uvicorn ai_proxy.main:app --reload --host 127.0.0.1 --port 8011
    ```
    The service will be available at `http://localhost:8011`
### Development with ngrok
For testing webhooks or providing a temporary public URL to your local instance:
- Install [ngrok](https://ngrok.com/)
- Run: `ngrok http 8011`
- Use the public ngrok URL provided.

## Development vs Production

The development environment is designed to be separate from production while maintaining environment parity:

### Development Mode (`make dev`)
- **Frontend:** Vite dev server with HMR (port 5174)
- **Backend API:** FastAPI with `--reload` flag
- **Volumes:** Source code mounted for hot reload
- **Compose files:** `docker-compose.yml` + `docker-compose.dev.yml`
- **Container name:** `logs-ui-web-dev` (different from production)

### Production Mode (`make up`)
- **Frontend:** Nginx serving pre-built static files (port 5173)
- **Backend API:** FastAPI with `--reload` (already optimized for production)
- **Volumes:** Only necessary files mounted
- **Compose file:** `docker-compose.yml` only
- **Container name:** `logs-ui-web`

**Key points:**
- ✅ Production config never modified by dev mode
- ✅ Switch between modes without data loss
- ✅ Same Docker network for both environments

### Dev Traefik note

When running `make dev`, a lightweight Traefik instance is started from `docker-compose.dev.yml`.
- Dev Traefik uses `traefik/traefik.dev.yml` and `traefik/dynamic.dev.yml` (file provider).
- It does not request Let's Encrypt certificates; TLS is disabled for dev routing.
- Recommended /etc/hosts entries for local testing:
  - `127.0.0.1 localhost`
  - `127.0.0.1 logs.localhost`
  - `127.0.0.1 logs-api.localhost`
  - `127.0.0.1 traefik.localhost`

Access via Traefik in dev:
- `http://logs.localhost:51999/` -> Vite dev server (same as on localhost:5174)
- `http://logs-api.localhost:51999/ui/health` -> Logs UI API (same as on localhost:8124)
- `http://localhost:51999/health` -> AI Proxy API (same as on localhost:8123)
- `http://traefik.localhost:51999` -> Traefik dashboard

---

## Testing

**⚠️ Important: All tests must run in Docker containers only!**

This project mandates Docker-only testing for consistent environments and reproducible results; tests fail if run outside Docker.

### Running Tests

Use the Makefile commands to run tests in Docker:

```bash
# Run all tests
make test

# Run only unit tests
make test-unit

# Run only integration tests
make test-integration

# Run tests with coverage report
make coverage

# Run specific test file or function
make test-specific TEST=tests/unit/test_config.py
make test-specific TEST=tests/unit/test_config.py::TestSettings::test_init_with_env_vars

# Run tests in watch mode (for development)
make test-watch

# Run UI unit tests
make test-ui

# Run UI E2E tests
make test-ui-e2e

# See all make commands
make help
```

## Production Deployment Details

The project features a **fully automated deployment script** for clean Ubuntu servers, managing everything from dependencies to SSL setup in one command.

```bash
# Deploy to any clean server (fully automated) or upload latest changes to an old production server
DEPLOY_HOST=your-server ./scripts/deploy-production.sh

# Rollback to previous version
DEPLOY_HOST=your-server ./scripts/deploy-production.sh --rollback

# List available backups
DEPLOY_HOST=your-server ./scripts/deploy-production.sh --list-backups

# Restore specific backup
DEPLOY_HOST=your-server ./scripts/deploy-production.sh --restore-backup backup-filename.tar.gz
```

### Automated Setup Features:

**Zero-Configuration Deployment:**
- **Auto dependency installation**: rsync, Docker, Docker Compose
- **Remote directory creation**: creates `/root/ai-proxy` if needed
- **Universal Docker Compose support**: auto-detects v1 or v2
- **First deployment detection**: syncs local `.env` on first deployment
- **Auto HTTPS setup**: generates domain via nip.io and real email

**HTTPS Auto-Configuration:**
- Detects public IP and generates `ai-proxy.YOUR-IP.nip.io` domain
- Issues Let's Encrypt SSL certificates (info@techsupport-services.com)
- Supports nip.io, sslip.io, ngrok, and custom domains

**Safety Features:**
- Automatic backup before deployment
- Preserves SSL certificates, environment configuration, production logs, and Traefik configuration
- Only syncs specific code files, never deleting production configs

**Deployment Process:**
- Check prerequisites and install
- Perform health check before deployment
- Create timestamped backup
- Sync changed code files
- Set up HTTPS if needed
- Rebuild and restart containers
- Verify deployment health
- Test basic functionality
- Clean up old backups (keep last 5)

**Environment Variables:**
- `DEPLOY_HOST` - Target server hostname (required)
- `DEPLOY_PATH` - Remote deployment path (default: `/root/ai-proxy`)

### Rollback Capability

If something goes wrong, you can quickly rollback:

```bash
DEPLOY_HOST=your-server ./scripts/deploy-production.sh --rollback
```

This will restore the most recent backup and restart services.

## HTTPS Configuration Details

The service uses **Traefik** as a reverse proxy with automatic **Let's Encrypt** SSL certificate management. HTTPS is configured automatically during deployment.

### Automatic HTTPS Setup

The deployment script features a non-interactive HTTPS setup tool (`scripts/setup-https.sh`) that automatically detects the server's public IP, generates a domain via free DNS (nip.io by default), configures Let's Encrypt SSL certificates, uses a realistic email for registration, and modifies only HTTPS settings in .env while preserving API keys.

#### Manual HTTPS Setup Options

You can also run the HTTPS setup manually with different options:

```bash
# Use default settings (nip.io)
./scripts/setup-https.sh -e your-email@example.com

# Use sslip.io service
./scripts/setup-https.sh -s sslip.io -e your-email@example.com -n myapp

# Use custom domain
./scripts/setup-https.sh -s custom -d api.example.com -e your-email@example.com

# Use ngrok domain
./scripts/setup-https.sh -s ngrok -d abc123.ngrok.io -e your-email@example.com
```

### Custom Port Configuration

By default, the Traefik service uses standard HTTP (80) and HTTPS (443) ports. You can customize these by setting the `HTTP_PORT` and `HTTPS_PORT` variables in your `.env` file:

```env
HTTP_PORT=9080  # Example: Change HTTP to 9080
HTTPS_PORT=9443 # Example: Change HTTPS to 9443
```

⚠️ **Note**: Custom ports may prevent Let's Encrypt from issuing certificates, as it requires access to port 80 for domain validation.

### Let's Encrypt Certificates and Production Deployment with Custom Ports

Let's Encrypt certificates are valid for **90 days** and auto-renewed by Traefik. For initial issuance, access to HTTP (port 80) or HTTPS (port 443) is required. If these ports are occupied, follow this process:

1. **Stop** services using ports 80/443 (e.g., Docker containers).
2. **Change** your `.env` file to standard ports (80 and 443).
3. **Deploy** the AI Proxy service.
4. **Check** Traefik logs for certificate acquisition.
5. **Revert** your `.env` file to custom ports.
6. **Redeploy** the AI Proxy service on custom ports.
7. **Restart** any stopped services.

This ensures Traefik can obtain and renew certificates even when standard ports are in use, keeping your service secure.

## Advanced Log Storage System

The project includes an advanced SQLite-based log storage system (partitioned DB, optional FTS5, dialog grouping and bundle utilities). For full documentation, examples and troubleshooting, see [ai-docs/advanced-log-storage.md](ai-docs/advanced-log-storage.md).

## Project Structure

```
ai-proxy/
├── ai_proxy/               # Main AI Proxy application (FastAPI)
│   ├── adapters/          # AI provider adapters (Gemini, OpenRouter)
│   ├── api/v1/            # REST API endpoints (chat completions, models)
│   ├── core/              # Core functionality (config, routing)
│   ├── logdb/             # Advanced SQLite-based log storage system
│   │   ├── cli/           # Command-line interface modules
│   │   ├── parsers/       # Log file parsers
│   │   ├── processing/    # Log processing utilities
│   │   ├── utils/         # Helper utilities
│   │   ├── schema.py      # Database schema definitions
│   │   ├── ingest.py      # Log ingestion logic
│   │   ├── fts.py         # Full-text search management
│   │   ├── dialogs.py     # Dialog/conversation grouping
│   │   ├── bundle.py      # Bundle creation/verification
│   │   ├── transport.py   # File transfer utilities
│   │   ├── merge.py       # Database merging utilities
│   │   └── partitioning.py # Date-based partitioning
│   ├── logging/           # Application logging configuration
│   ├── security/          # Authentication and security
│   └── main.py            # FastAPI application entry point
├── ai_proxy_ui/           # Logs UI API application (FastAPI)
│   ├── routers/           # API route handlers
│   ├── services/          # Business logic services
│   ├── components/        # Reusable components
│   ├── config/            # Configuration utilities
│   └── main.py            # FastAPI application entry point
├── ui/                    # React frontend for logs visualization
│   ├── src/               # React application source
│   ├── tests-e2e/         # End-to-end tests (Playwright)
│   ├── dist/              # Built production assets
│   ├── Dockerfile*        # Container definitions
│   ├── package.json       # Node.js dependencies and scripts
│   ├── vite.config.ts     # Vite build configuration
│   ├── vitest.config.ts   # Testing configuration
│   └── nginx.conf         # Nginx configuration for serving
├── ai-docs/               # Project documentation and planning
│   ├── archive/           # Archived project plans
│   ├── *.md               # Current project documentation files
├── tests/                 # Comprehensive test suite
│   ├── unit/              # Unit tests
│   ├── integration/       # Integration tests
│   ├── functional/        # Functional/API tests
│   ├── conftest.py        # Test configuration and fixtures
│   └── README.md          # Testing documentation
├── scripts/               # Utility and deployment scripts
│   ├── logdb              # Log database management script
│   ├── deploy-production.sh # Automated production deployment
│   ├── setup-https.sh     # HTTPS certificate setup
│   ├── test-https.sh      # HTTPS testing utilities
│   ├── container-entrypoint.sh # Docker container entry point
│   ├── ensure-deployment-timestamp.sh # Deployment timestamp management
│   ├── analyze_code_size.py # Code size analysis
│   └── check_module_dependencies.py # Dependency checking
├── traefik/               # Reverse proxy configuration
│   ├── traefik.yml        # Production Traefik configuration
│   ├── traefik.dev.yml    # Development Traefik configuration
│   ├── dynamic.yml        # Production routing rules
│   └── dynamic.dev.yml    # Development routing rules
├── logs/                  # Application logs and databases
│   ├── db/                # SQLite partitions (YYYY/MM/*.sqlite3)
│   │   ├── control.sqlite3 # Partition metadata database
│   │   └── monthly/       # Merged monthly databases
│   ├── models/            # Model-specific logs (GPT, Claude, Gemini, etc.)
│   ├── downloaded/        # Downloaded log bundles
│   ├── *.log              # Traditional application logs
│   ├── coverage.*         # Test coverage reports
│   └── unit-test-results.xml # Test result outputs
├── bundles/               # Log bundles for backup/transfer
├── certs/                 # SSL certificates (Let's Encrypt)
├── tmp/                   # Temporary files and configurations
├── docker-compose.yml     # Production deployment configuration
├── docker-compose.dev.yml # Development environment configuration
├── docker-compose.test.yml # Testing environment configuration
├── Dockerfile             # Main application container
├── Makefile               # Development and deployment automation
├── pyproject.toml         # Python project configuration (Poetry)
├── poetry.lock            # Dependency lock file
├── config.yml             # Application configuration
├── .env.example           # Environment variables template
├── wait-for-service.sh    # Service readiness checking script
└── README.md              # Project documentation
```
