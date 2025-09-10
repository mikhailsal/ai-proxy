# AI Proxy Service

This service acts as a drop-in replacement for the OpenAI API, providing a unified interface to route requests to various Large Language Model (LLM) providers like OpenRouter and Google Gemini.

It is built with Python and FastAPI and is designed to be lightweight, fast, and easy to deploy with **HTTPS support** and automatic SSL certificate management.

**🚀 Current Implementation Status**: The advanced log storage system (Stages A-H) is fully implemented and production-ready, providing SQLite-based log storage with full-text search, dialog grouping, and portable bundles for backup and transfer.

## Features

*   **OpenAI API Compatibility**: `POST /v1/chat/completions` endpoint.
*   **Provider Routing**: Currently supports proxying requests to [OpenRouter](https://openrouter.ai/) and **Google Gemini API**.
*   **Model Mapping**: Configure model aliases or use wildcards to map friendly names to specific provider models (e.g., `gpt-4` -> `openai/gpt-4`, `gemini-pro` -> `gemini:gemini-1.5-pro-latest`).
*   **Authentication**: Secure the proxy with API keys.
*   **HTTPS Support**: Automatic SSL certificate management with Let's Encrypt via Traefik.
*   **Advanced Log Storage System**: SQLite-based log storage with full-text search, dialog grouping, and portable bundles for easy transfer and backup.
*   **Structured Logging**: JSON-formatted logs for easy parsing and monitoring.
*   **Containerized**: Ready to deploy with Docker and Docker Compose.

## Getting Started

This guide will walk you through setting up the AI Proxy service with HTTPS.

### Prerequisites

*   Docker and Docker Compose.
*   A domain name.
*   An email address for SSL certificate registration.

### Quick HTTPS Setup

1.  **Clone the repository:**
    ```bash
    git clone <repository-url>
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
    docker-compose up -d
    ```

5.  **Test the setup:**
    ```bash
    ./scripts/test-https.sh
    ```

Your service will be available at:
- **AI Proxy**: `https://your-domain.com`
- **Traefik Dashboard**: `https://traefik.your-domain.com`

### Domain Options

*   **Free Temporary Domains**: For quick testing, you can use services like `nip.io` or `sslip.io`. Set `DOMAIN=myapp.YOUR-SERVER-IP.nip.io`.
*   **Real Domain**: For production, point an A record from your domain registrar to your server's IP address.

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
# Enable log storage (default: false)
LOGDB_ENABLED=true

# Enable full-text search (default: false)
LOGDB_FTS_ENABLED=true

# Enable dialog grouping (default: false)
LOGDB_GROUPING_ENABLED=true

# Configure partition granularity (default: daily)
LOGDB_PARTITION_GRANULARITY=daily
```

### Basic Operations

```bash
# Initialize database for today
poetry run python -m ai_proxy.logdb.cli init

# Ingest logs from the last 7 days
poetry run python -m ai_proxy.logdb.cli ingest --from ./logs --since 2025-09-01 --to 2025-09-07

# Build full-text search index
poetry run python -m ai_proxy.logdb.cli fts build --since 2025-09-01 --to 2025-09-07

# Create a portable bundle for backup/transfer
poetry run python -m ai_proxy.logdb.cli bundle create --since 2025-09-01 --to 2025-09-07 --out ./backup-2025-09-01.tgz

# Transfer bundle to another server
poetry run python -m ai_proxy.logdb.cli bundle transfer ./backup-2025-09-01.tgz /path/to/destination/

# Import bundle on destination server
poetry run python -m ai_proxy.logdb.cli bundle import ./backup-2025-09-01.tgz --dest ./logs/db
```

### Search Examples

Once your logs are indexed, you can perform advanced searches:

```sql
-- Find conversations about specific topics
SELECT * FROM request_text_index WHERE request_text_index MATCH 'machine learning OR AI';

-- Find error patterns with proximity search
SELECT * FROM request_text_index WHERE request_text_index MATCH 'error NEAR/5 timeout';

-- Find conversations by model
SELECT r.* FROM requests r
JOIN request_text_index fts ON r.request_id = fts.request_id
WHERE fts.model_original LIKE '%gpt-4%';

-- Group conversations by API key and time window
SELECT dialog_id, COUNT(*) as message_count,
       MIN(ts) as start_time, MAX(ts) as end_time
FROM requests
WHERE dialog_id IS NOT NULL
GROUP BY dialog_id
ORDER BY start_time DESC;
```

## Production Deployment

The project includes a safe production deployment script that preserves important files while updating the application code.

```bash
# Deploy latest changes to production
DEPLOY_HOST=your-server ./scripts/deploy-production.sh
```

For more details on deployment, local development, and testing, see the [Development Guide](DEVELOPMENT.md).

## Security Features

- 🔐 **API Key Authentication**: Secure access control
- 🛡️ **HTTPS Encryption**: All traffic encrypted in transit
- 🔒 **Security Headers**: HSTS, secure redirects
- 📊 **Request Logging**: Comprehensive audit trail
- 🚫 **Rate Limiting**: Built-in protection (via Traefik)

## Monitoring

- **Health Check**: `https://your-domain.com/health`
- **Traefik Dashboard**: `https://traefik.your-domain.com`
- **Logs**: Structured JSON logs are available in the `logs/` directory.
- **Log Database**: SQLite-based log storage with advanced search capabilities in `logs/db/` directory.
- **Log Bundles**: Portable compressed archives for backup and transfer in `bundles/` directory.
