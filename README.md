# AI Proxy Service

This service acts as a drop-in replacement for the OpenAI API (and others in the future), providing a unified interface to route requests to various Large Language Model (LLM) providers like OpenRouter and Google Gemini.

It is built with Python and FastAPI and is designed to be lightweight, fast, and easy to deploy with **HTTPS support** and automatic SSL certificate management.

Also we have a Logs UI and Analysis System that allows you to view and analyze the logs in a more user-friendly way (written in React)

## Features

*   **OpenAI API Compatibility**: `POST /v1/chat/completions` endpoint.
*   **Provider Routing**: Currently supports proxying requests to [OpenRouter](https://openrouter.ai/) and **Google Gemini API**.
*   **Model Mapping**: Configure model aliases or use wildcards to map friendly names to specific provider models (e.g., `gpt-4` -> `openai/gpt-4`, `gemini-pro` -> `gemini:gemini-1.5-pro-latest`).
*   **Authentication**: Secure the proxy with API keys.
*   **HTTPS Support**: Automatic SSL certificate management with Let's Encrypt via Traefik.
*   **Advanced Log Storage System**: SQLite-based log storage with full-text search, dialog grouping, and portable bundles for easy transfer and backup.
*   **Structured Logging**: JSON-formatted logs for easy parsing and monitoring.
*   **Containerized**: Ready to deploy with Docker and Docker Compose.
*   **Logs UI and Analysis System**: A React-based UI and analysis system for the logs.

## Getting Started

This guide will walk you through setting up the AI Proxy service with HTTPS.

### Prerequisites

*   Docker and Docker Compose.
*   A domain name.
*   An email address for SSL certificate registration.

### Quick HTTPS Setup

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/mihsal/ai-proxy.git
    cd ai-proxy
    ```

2.  **Run the HTTPS setup script:**
    This script will generate the necessary configuration files.
    ```bash
    ./scripts/setup-https.sh
    ```

3.  **Configure your domain and API keys:**
    Edit the `.env` file with your domain, credentials, and optional port configuration:
    ```bash
    # Required for HTTPS
    DOMAIN=your-domain.com
    ACME_EMAIL=your-email@example.com

    # Your API configuration
    API_KEYS=your-secret-key-1,your-secret-key-2
    OPENROUTER_API_KEY=your-openrouter-api-key
    GEMINI_API_KEY=your-gemini-api-key

    # Optional: Custom Port Configuration for non-standard ports
    # HTTP_PORT=8080
    # HTTPS_PORT=8443
    ```

4.  **Deploy with HTTPS:**
    ```bash
    docker compose up -d
    ```

5.  **Test the setup:**
    ```bash
    ./scripts/test-https.sh
    ```

Your service will be available at:
- **AI Proxy**: `https://your-domain.com`
- **Traefik Dashboard**: `https://traefik.your-domain.com`
 - **Logs UI (web)**: `https://logs.your-domain.com`
 - **Logs UI API**: `https://logs-api.your-domain.com`

### Domain Options

*   **Free Temporary Domains**: Use `nip.io` or `sslip.io` with your public IP (e.g., `ai-proxy.192.168.1.100.nip.io`). The setup script detects your IP automatically.
*   **Real Domain**: Purchase from any registrar and point A record to your server IP. Use `./scripts/setup-https.sh -s custom -d your-domain.com`
*   **Ngrok Tunnel**: For development, install ngrok and use `./scripts/setup-https.sh -s ngrok -d your-ngrok-url`

## Usage

Make requests to the proxy service just as you would with the OpenAI API:

```bash
curl https://your-domain.com/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-secret-key-1" \
  -d '{
    "model": "gpt-4",
    "messages": [
      {
        "role": "user",
        "content": "What is the capital of France?"
      }
    ]
  }'
```

The `model` field will be automatically mapped based on your `config.yml` file.

## Advanced Log Storage System

The AI Proxy includes a powerful SQLite-based log storage system designed for portability, searchability, and efficient data management. This system transforms your text logs into a structured database with advanced features.

### Key Capabilities

*   **Full-Text Search**: Find conversations using natural language queries (e.g., "timeout NEAR/3 retry", "user asked about France")
*   **Dialog Grouping**: Automatically group related messages into conversations based on time windows and API keys
*   **Portable Bundles**: Package logs into compressed archives for easy backup and transfer between servers
*   **Performance Optimized**: Uses SQLite with WAL mode and efficient indexing for fast queries
*   **Incremental Processing**: Safely resume log ingestion from where it left off
*   **Multi-Server Support**: Deduplicate logs from multiple servers with stable server identities

### Quick Start with Log Storage

Enable the log storage system by setting environment variables:

```bash
# Enable log storage system (default: false)
LOGDB_ENABLED=true

# Enable full-text search (default: false)
LOGDB_FTS_ENABLED=true

# Enable dialog grouping (default: false)
LOGDB_GROUPING_ENABLED=true

# Configure partition granularity: daily|weekly (default: daily)
LOGDB_PARTITION_GRANULARITY=daily

# Include raw logs in bundles (default: false)
LOGDB_BUNDLE_INCLUDE_RAW=false

# Concurrent file processing (default: 2)
LOGDB_IMPORT_PARALLELISM=2

# Memory limit for processing (default: 256)
LOGDB_MEMORY_CAP_MB=256

# When true, delete daily source partitions after successful weekly/monthly merges
# performed by `logdb auto` or programmatic merges. Default: false
LOGDB_CLEANUP_AFTER_MERGE=false
```

### Basic Operations

**Use the convenient bash script `./scripts/logdb` instead of long commands:**

```bash
# Run auto ingest and compaction (default when no args supplied)
./scripts/logdb

# Initialize database for today
./scripts/logdb init

# Ingest logs from the last 7 days
./scripts/logdb ingest --from ./logs --since 2025-09-01 --to 2025-09-07

# Build full-text search index
./scripts/logdb fts build --since 2025-09-01 --to 2025-09-07

# Create a portable bundle for backup/transfer
./scripts/logdb bundle create --since 2025-09-01 --to 2025-09-07 --out ./backup-2025-09-01.tgz

# Transfer bundle to another server
./scripts/logdb bundle transfer ./backup-2025-09-01.tgz /path/to/destination/

# Import bundle on destination server
./scripts/logdb bundle import ./backup-2025-09-01.tgz --dest ./logs/db
```

## Production Deployment

The project includes a safe production deployment script that preserves important files while updating the application code.

```bash
# Deploy from scratch or upload latest changes to production
DEPLOY_HOST=your-server ./scripts/deploy-production.sh
```

For more details on deployment, local development, and testing, see the [Development Guide](DEVELOPMENT.md).

## Security Features

- 🔐 **API Key Authentication**: Secure access control
- 🛡️ **HTTPS Encryption**: All traffic encrypted in transit
- 🔒 **Security Headers**: HSTS, secure redirects
- 📊 **Request Logging**: Comprehensive audit trail
- 🚫 **Rate Limiting**: Optional Traefik middleware (disabled by default)

## Monitoring

- **Health Check**: `https://your-domain.com/health`
- **Traefik Dashboard**: `https://traefik.your-domain.com`
- **Logs**: Structured JSON logs are available in the `logs/` directory.
- **Log Database**: SQLite-based log storage with advanced search capabilities in `logs/db/` directory.
- **Log Bundles**: Portable compressed archives for backup and transfer in `bundles/` directory.

## Logs UI (Stage U1)

The repository includes a separate Logs UI API and a static web UI scaffold.

- Logs UI API (FastAPI): served by the `logs-ui-api` service, health endpoints at `/ui/health` and `/ui/v1/health`.
  - Note: `/ui/v1/*` endpoints require a Bearer token from `LOGUI_API_KEYS` or `LOGUI_ADMIN_API_KEYS`. The legacy `/ui/health` endpoint is public.
- Logs UI Web (Nginx): served by the `logs-ui-web` service, static page with a Connect message.

Environment variables (add to `.env` as needed):

```bash
# Logs UI API keys (comma-separated)
LOGUI_API_KEYS=logs-ui-user-key-1
LOGUI_ADMIN_API_KEYS=logs-ui-admin-key-1
# Allowed origins for CORS
LOGUI_ALLOWED_ORIGINS=https://logs.your-domain.com,http://localhost:5173
# Logs UI configuration
LOGUI_RATE_LIMIT_RPS=10
LOGUI_DB_ROOT=./logs/db
# Optional
LOGUI_ENABLE_TEXT_LOGS=false
LOGUI_SSE_HEARTBEAT_MS=15000
```

## Quick commands

Use these minimal commands to run and manage the project (from the repository root):

```bash
# Start services in background (build if needed)
make up

# Stop all services
make down

# Install Python deps with Poetry
make install

# Development mode with hot reload (for Logs UI development)
make dev
# Access at http://localhost:5174 (port 5174 for dev, 5173 for production)
```

For Logs UI development with instant hot reload, see the [Development Guide](DEVELOPMENT.md#quick-start-development-environment-with-hot-reload-).
