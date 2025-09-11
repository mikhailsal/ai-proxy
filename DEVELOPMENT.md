# Development Guide

This guide provides instructions for developers who want to contribute to the AI Proxy service, run it locally, or understand its internal workings. For user-facing documentation, see `README.md`.

## Prerequisites

*   Python 3.10+
*   [Poetry](https://python-poetry.org/) for dependency management.
*   Docker and Docker Compose.
*   A domain name (for testing HTTPS).

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
    Edit `.env` with your configuration. For local development, you mainly need API keys. You can set a custom `HTTP_PORT` if needed.
    ```bash
    # Example .env for local development
    API_KEYS=your-secret-key
    OPENROUTER_API_KEY=your-openrouter-key
    GEMINI_API_KEY=your-gemini-key
    # HTTP_PORT=8123
    ```

3.  **Run the service:**
    ```bash
    poetry run uvicorn ai_proxy.main:app --reload
    ```
    The service will be available at `http://localhost:8123` (or your custom `HTTP_PORT`).

### Development with ngrok
For testing webhooks or providing a temporary public URL to your local instance:
- Install [ngrok](https://ngrok.com/)
- Run: `ngrok http 8123` (replace `8123` with your `HTTP_PORT`)
- Use the public ngrok URL provided.

### Docker Deployment (HTTP only)

1.  **Build the Docker image:**
    ```bash
    docker build -t ai-proxy .
    ```

2.  **Run the Docker container:**
    ```bash
    docker run -d --env-file .env -p 8123:8123 --name ai-proxy-container ai-proxy
    ```

## Testing

**⚠️ Important: All tests must run in Docker containers only!**

This project enforces Docker-only testing to ensure consistent environments, proper isolation, and reproducible results. Tests will automatically fail if run outside of Docker.

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
```

### UI Unit Tests (Dockerized Node)

Run the Logs UI unit tests without installing Node locally. Use the `ui-test` target, which runs tests inside a Node 20 Docker container:

```bash
# Run UI unit tests
make ui-test
```

This target mounts the `ui/` folder and executes:

```bash
docker run --rm -v $(PWD)/ui:/app -w /app node:20 bash -lc "npm ci --no-audit --fund=false --loglevel=error && npm run test --silent"
```

### Direct Docker Commands

You can also run tests directly with Docker Compose:

```bash
# Run all tests
docker run --rm -e DOCKER_CONTAINER=true -v $(PWD):/app ai-proxy poetry run pytest tests/

# Run specific test file
docker run --rm -e DOCKER_CONTAINER=true -v $(PWD):/app ai-proxy poetry run pytest tests/unit/test_config.py -v

# Run with coverage
docker run --rm -e DOCKER_CONTAINER=true -v $(PWD):/app ai-proxy poetry run pytest tests/ --cov=ai_proxy --cov-report=html
```

### Why Docker-Only Testing?

- **Consistent Environment**: All developers and CI/CD systems use identical test environments
- **Isolation**: Tests run in clean, isolated containers without interference from host system
- **Reproducibility**: Results are consistent across different machines and environments
- **Dependencies**: All required dependencies and services are properly containerized

## Production Deployment Details

The project includes a **fully automated production deployment script** that can deploy to any clean Ubuntu server with a single command. The script handles everything from dependency installation to SSL certificate setup.

```bash
# Deploy to any clean server (fully automated)
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
- ✅ **Automatic dependency installation**: rsync, Docker, Docker Compose
- ✅ **Remote directory creation**: creates `/root/ai-proxy` if needed
- ✅ **Universal Docker Compose support**: detects and uses v1 or v2 automatically
- ✅ **First deployment detection**: syncs local `.env` file on first deployment only
- ✅ **Automatic HTTPS setup**: generates domain using nip.io service and real email

**HTTPS Auto-Configuration:**
- ✅ **Public IP detection**: automatically detects server's public IP
- ✅ **Domain generation**: creates `ai-proxy.YOUR-IP.nip.io` domain
- ✅ **SSL certificates**: Let's Encrypt certificates with real email (`info@techsupport-services.com`)
- ✅ **Multiple domain services**: supports nip.io (default), sslip.io, ngrok, custom domains

**Safety Features:**
- ✅ Creates automatic backup before deployment
- ✅ Preserves SSL certificates (`certs/` directory)
- ✅ Preserves environment configuration (existing `.env` files)
- ✅ Preserves production logs (`logs/` directory)
- ✅ Preserves Traefik configuration (`traefik/` directory)
- ✅ Only syncs specific code files (never deletes production configs)

**Deployment Process:**
- ✅ Prerequisites check and installation
- ✅ Health check before deployment (if service exists)
- ✅ Creates timestamped backup
- ✅ Syncs only changed code files
- ✅ HTTPS setup (if not configured)
- ✅ Rebuilds and restarts containers
- ✅ Verifies deployment with health checks
- ✅ Tests basic functionality
- ✅ Cleans up old backups (keeps last 5)

**Environment Variables:**
- `DEPLOY_HOST` - Target server hostname (required)
- `DEPLOY_PATH` - Remote deployment path (default: `/root/ai-proxy`)

### Clean Server Deployment

The deployment script can now deploy to completely clean Ubuntu servers. It will automatically:

1. **Install Docker** using the official installation script
2. **Install rsync** if not available
3. **Create deployment directory** if it doesn't exist
4. **Copy your local .env file** on first deployment (preserves API keys)
5. **Set up HTTPS** with automatic domain and SSL certificates
6. **Deploy and start** all services

Example deployment to a fresh server:
```bash
# This works on any clean Ubuntu server with SSH access
DEPLOY_HOST=new-server ./scripts/deploy-production.sh
```

The script will output something like:
```
✅ Created remote directory: /root/ai-proxy
✅ Docker installed successfully
✅ Using Docker Compose v2: docker compose
✅ First deployment detected - syncing local .env file
✅ HTTPS setup completed successfully
✅ Generated domain: ai-proxy.45.138.25.40.nip.io
✅ Service is healthy after deployment
```

### Rollback Capability

If something goes wrong, you can quickly rollback:

```bash
DEPLOY_HOST=your-server ./scripts/deploy-production.sh --rollback
```

This will restore the most recent backup and restart services.

## Production Testing

To test your production deployment, you can use these commands that automatically detect your domain and API keys from the `.env` file.

### Auto-Detection Script
```bash
# Extract configuration from .env file
DOMAIN=$(grep '^DOMAIN=' .env | cut -d= -f2)
HTTPS_PORT=$(grep '^HTTPS_PORT=' .env | cut -d= -f2)
API_KEY=$(grep '^API_KEYS=' .env | cut -d= -f2 | cut -d, -f1)

# Use default HTTPS port if not specified
if [ -z "$HTTPS_PORT" ]; then
    HTTPS_PORT=443
fi

# Construct the base URL
if [ "$HTTPS_PORT" = "443" ]; then
    BASE_URL="https://$DOMAIN"
else
    BASE_URL="https://$DOMAIN:$HTTPS_PORT"
fi

echo "Testing AI Proxy at: $BASE_URL"
echo "Using API Key: ${API_KEY:0:10}..."
```

### Health Check
```bash
# Auto-detect domain and port
DOMAIN=$(grep '^DOMAIN=' .env | cut -d= -f2)
HTTPS_PORT=$(grep '^HTTPS_PORT=' .env | cut -d= -f2)
BASE_URL="https://$DOMAIN${HTTPS_PORT:+:$HTTPS_PORT}"

curl -s "$BASE_URL/health"
```

### Test Regular Chat Completion
```bash
# Auto-detect configuration
DOMAIN=$(grep '^DOMAIN=' .env | cut -d= -f2)
HTTPS_PORT=$(grep '^HTTPS_PORT=' .env | cut -d= -f2)
API_KEY=$(grep '^API_KEYS=' .env | cut -d= -f2 | cut -d, -f1)
BASE_URL="https://$DOMAIN${HTTPS_PORT:+:$HTTPS_PORT}"

curl -s "$BASE_URL/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $API_KEY" \
  -d '{
    "model": "gemini-pro",
    "messages": [
      {
        "role": "user",
        "content": "Say hello in one word"
      }
    ]
  }'
```

### Test Streaming Chat Completion
```bash
# Auto-detect configuration
DOMAIN=$(grep '^DOMAIN=' .env | cut -d= -f2)
HTTPS_PORT=$(grep '^HTTPS_PORT=' .env | cut -d= -f2)
API_KEY=$(grep '^API_KEYS=' .env | cut -d= -f2 | cut -d, -f1)
BASE_URL="https://$DOMAIN${HTTPS_PORT:+:$HTTPS_PORT}"

curl -s "$BASE_URL/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $API_KEY" \
  -d '{
    "model": "gemini-pro",
    "messages": [
      {
        "role": "user",
        "content": "Count from 1 to 3"
      }
    ],
    "stream": true
  }' | head -10
```

### Test OpenRouter Model
```bash
# Auto-detect configuration
DOMAIN=$(grep '^DOMAIN=' .env | cut -d= -f2)
HTTPS_PORT=$(grep '^HTTPS_PORT=' .env | cut -d= -f2)
API_KEY=$(grep '^API_KEYS=' .env | cut -d= -f2 | cut -d, -f1)
BASE_URL="https://$DOMAIN${HTTPS_PORT:+:$HTTPS_PORT}"

curl -s "$BASE_URL/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $API_KEY" \
  -d '{
    "model": "mistral-small",
    "messages": [
      {
        "role": "user",
        "content": "Say hi briefly"
      }
    ],
    "stream": true
  }' | head -5
```

### Remote Testing (SSH)
If you're testing from a different machine, you can run these commands via SSH:

```bash
# Test health endpoint
ssh your-server "cd /path/to/ai-proxy && DOMAIN=\$(grep '^DOMAIN=' .env | cut -d= -f2) && HTTPS_PORT=\$(grep '^HTTPS_PORT=' .env | cut -d= -f2) && curl -s \"https://\$DOMAIN\${HTTPS_PORT:+:\$HTTPS_PORT}/health\""

# Test chat completion
ssh your-server "cd /path/to/ai-proxy && DOMAIN=\$(grep '^DOMAIN=' .env | cut -d= -f2) && HTTPS_PORT=\$(grep '^HTTPS_PORT=' .env | cut -d= -f2) && API_KEY=\$(grep '^API_KEYS=' .env | cut -d= -f2 | cut -d, -f1) && curl -s \"https://\$DOMAIN\${HTTPS_PORT:+:\$HTTPS_PORT}/v1/chat/completions\" -H \"Content-Type: application/json\" -H \"Authorization: Bearer \$API_KEY\" -d '{\"model\": \"gemini-pro\", \"messages\": [{\"role\": \"user\", \"content\": \"Hello\"}]}'"
```

## HTTPS Configuration Details

The service uses **Traefik** as a reverse proxy with automatic **Let's Encrypt** SSL certificate management. HTTPS is configured automatically during deployment.

### Automatic HTTPS Setup

The deployment script includes a non-interactive HTTPS setup tool (`scripts/setup-https.sh`) that:

- **Automatically detects your server's public IP**
- **Generates a domain** using free DNS services (nip.io by default)
- **Configures SSL certificates** with Let's Encrypt
- **Uses realistic email** for certificate registration
- **Only modifies HTTPS settings** in .env (preserves API keys)

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

By default, the service uses standard HTTP (80) and HTTPS (443) ports. You can customize these by setting the `HTTP_PORT` and `HTTPS_PORT` variables in your `.env` file:

```env
HTTP_PORT=9080  # Example: Change HTTP to 9080
HTTPS_PORT=9443 # Example: Change HTTPS to 9443
```

⚠️ **Note**: Custom ports may prevent Let's Encrypt from issuing certificates, as it requires access to port 80 for domain validation.

### Let's Encrypt Certificates and Production Deployment

Let's Encrypt certificates are valid for **90 days** and are automatically renewed by Traefik. However, for initial certificate issuance, Let's Encrypt requires access to standard HTTP (port 80) or HTTPS (port 443) ports for domain validation.

If your server has other services occupying ports 80/443, you can use the following strategy for initial certificate acquisition:

1.  **Identify and temporarily stop** the service(s) occupying ports 80/443 (e.g., another Docker container).
2.  **Reconfigure** your `.env` file to use standard ports (80 and 443).
3.  **Deploy** the AI Proxy service.
4.  **Verify** certificate acquisition (check Traefik logs).
5.  **Reconfigure** your `.env` file back to your desired custom ports.
6.  **Redeploy** the AI Proxy service on custom ports.
7.  **Restart** the original service(s) that were temporarily stopped.

This process allows Traefik to obtain and renew certificates even when standard ports are generally in use by other applications, ensuring your service remains secure.

### Troubleshooting HTTPS

If HTTPS is not working:

1. **Check logs:**
   ```bash
   docker-compose logs traefik
   docker-compose logs ai-proxy
   ```

2. **Verify domain accessibility:**
   ```bash
   curl -I http://your-domain.com
   ```

3. **Test certificate generation:**
   - Let's Encrypt requires your domain to be publicly accessible
   - Check DNS propagation: `nslookup your-domain.com`
   - Verify ports 80 and 443 are open

4. **Run the test script:**
   ```bash
   ./scripts/test-https.sh
   ```

## Project Structure

```
ai-proxy/
├── ai_proxy/               # Main application code
│   └── logdb/             # Log storage system
│       ├── cli.py         # Command-line interface
│       ├── schema.py      # Database schema definitions
│       ├── ingest.py      # Log ingestion logic
│       ├── fts.py         # Full-text search management
│       ├── dialogs.py     # Dialog grouping logic
│       ├── bundle.py      # Bundle creation/verification
│       ├── transport.py   # File transfer utilities
│       ├── merge.py       # Database merging utilities
│       └── partitioning.py # Date-based partitioning
├── scripts/                # Setup and testing scripts
│   ├── setup-https.sh     # HTTPS configuration script
│   └── test-https.sh      # HTTPS testing script
├── logs/                   # Application logs and databases
│   ├── db/                # SQLite partitions (YYYY/MM/*.sqlite3)
│   │   └── monthly/       # Merged monthly databases
│   ├── models/            # Model-specific logs
│   └── *.log              # Traditional text logs
├── bundles/                # Log bundles for backup/transfer
├── docker-compose.yml     # Production deployment with HTTPS
├── Dockerfile             # Application container
├── .env.example          # Environment configuration template
└── README.md             # This file
```

## Advanced Log Storage System (Stages A-H Implemented)

The AI Proxy includes a comprehensive SQLite-based log storage system that transforms text logs into a powerful, searchable database. This system is designed for production use with features like incremental processing, full-text search, dialog grouping, and portable bundles.

### Core Features

*   **SQLite Storage**: Efficient partitioned database with WAL mode and optimized indexing
*   **Full-Text Search**: FTS5 virtual tables for natural language queries
*   **Dialog Grouping**: Automatic conversation grouping based on time windows and API keys
*   **Portable Bundles**: Compressed archives with integrity verification
*   **Incremental Processing**: Resume log ingestion safely from checkpoints
*   **Multi-Server Support**: Server identity management and deduplication

### Configuration

Enable log storage features via environment variables:

```bash
# Core settings
LOGDB_ENABLED=true                    # Enable log storage system (default: false)
LOGDB_PARTITION_GRANULARITY=daily     # Partition granularity: daily|weekly (default: daily)
LOGDB_IMPORT_PARALLELISM=2           # Concurrent file processing (default: 2)

# Feature flags
LOGDB_FTS_ENABLED=true               # Enable full-text search (default: false)
LOGDB_GROUPING_ENABLED=true          # Enable dialog grouping (default: false)
LOGDB_BUNDLE_INCLUDE_RAW=false       # Include raw logs in bundles (default: false)

# Performance caps
LOGDB_MEMORY_CAP_MB=256             # Memory limit for processing (default: 256)
```

### Database Schema

Each partition contains these tables:

- **`servers`**: Server identity and metadata
- **`requests`**: Main request/response data with timestamps and performance metrics
- **`ingest_sources`**: Incremental processing checkpoints
- **`request_text_index`**: FTS5 virtual table (when enabled)

### CLI Operations

**Use the convenient bash script `./scripts/logdb` to shorten commands:**

```bash
# Initialize database schema for today
./scripts/logdb init

# Initialize for specific date
./scripts/logdb init --date 2025-09-15

# Check database integrity
./scripts/logdb init --date 2025-09-15 | xargs sqlite3 "PRAGMA integrity_check;"
```

**Or use full commands:**

```bash
# Initialize database schema for today
python3 -m ai_proxy.logdb.cli init

# Initialize for specific date
python3 -m ai_proxy.logdb.cli init --date 2025-09-15

# Check database integrity
python3 -m ai_proxy.logdb.cli init --date 2025-09-15 | xargs sqlite3 "PRAGMA integrity_check;"
```

#### Log Ingestion

```bash
# Ingest logs for date range
./scripts/logdb ingest --from ./logs --since 2025-09-01 --to 2025-09-07

# Ingest with custom parallelism
LOGDB_IMPORT_PARALLELISM=4 ./scripts/logdb ingest --from ./logs --since 2025-09-01 --to 2025-09-07

# Check ingestion progress
sqlite3 logs/db/2025/09/ai_proxy_20250907.sqlite3 "SELECT * FROM ingest_sources;"
```

**Full commands:**

```bash
# Ingest logs for date range
python3 -m ai_proxy.logdb.cli ingest --from ./logs --since 2025-09-01 --to 2025-09-07

# Ingest with custom parallelism
LOGDB_IMPORT_PARALLELISM=4 python3 -m ai_proxy.logdb.cli ingest --from ./logs --since 2025-09-01 --to 2025-09-07

# Check ingestion progress
sqlite3 logs/db/2025/09/ai_proxy_20250907.sqlite3 "SELECT * FROM ingest_sources;"
```

#### Full-Text Search Management

```bash
# Build FTS index for date range
./scripts/logdb fts build --since 2025-09-01 --to 2025-09-07

# Remove FTS index (non-destructive)
./scripts/logdb fts drop --since 2025-09-01 --to 2025-09-07
```

**Full commands:**

```bash
# Build FTS index for date range
python3 -m ai_proxy.logdb.cli fts build --since 2025-09-01 --to 2025-09-07

# Remove FTS index (non-destructive)
python3 -m ai_proxy.logdb.cli fts drop --since 2025-09-01 --to 2025-09-07
```

#### Dialog Grouping

```bash
# Assign dialog IDs with 30-minute windows
./scripts/logdb dialogs assign --since 2025-09-01 --to 2025-09-07 --window 30m

# Use custom window size
./scripts/logdb dialogs assign --since 2025-09-01 --to 2025-09-07 --window 2h

# Clear dialog assignments
./scripts/logdb dialogs clear --since 2025-09-01 --to 2025-09-07
```

**Full commands:**

```bash
# Assign dialog IDs with 30-minute windows
python3 -m ai_proxy.logdb.cli dialogs assign --since 2025-09-01 --to 2025-09-07 --window 30m

# Use custom window size
python3 -m ai_proxy.logdb.cli dialogs assign --since 2025-09-01 --to 2025-09-07 --window 2h

# Clear dialog assignments
python3 -m ai_proxy.logdb.cli dialogs clear --since 2025-09-01 --to 2025-09-07
```

#### Bundle Operations

```bash
# Create bundle for date range
./scripts/logdb bundle create --since 2025-09-01 --to 2025-09-07 --out ./backup-2025-09-01.tgz

# Include raw log files in bundle
./scripts/logdb bundle create --since 2025-09-01 --to 2025-09-07 --out ./backup-2025-09-01.tgz --include-raw

# Verify bundle integrity
./scripts/logdb bundle verify ./backup-2025-09-01.tgz

# Transfer bundle with resume capability
./scripts/logdb bundle transfer ./backup-2025-09-01.tgz /dest/path/backup-2025-09-01.tgz

# Import bundle to destination
./scripts/logdb bundle import ./backup-2025-09-01.tgz --dest ./logs/db
```

**Full commands:**

```bash
# Create bundle for date range
python3 -m ai_proxy.logdb.cli bundle create --since 2025-09-01 --to 2025-09-07 --out ./backup-2025-09-01.tgz

# Include raw log files in bundle
python3 -m ai_proxy.logdb.cli bundle create --since 2025-09-01 --to 2025-09-07 --out ./backup-2025-09-01.tgz --include-raw

# Verify bundle integrity
python3 -m ai_proxy.logdb.cli bundle verify ./backup-2025-09-01.tgz

# Transfer bundle with resume capability
python3 -m ai_proxy.logdb.cli bundle transfer ./backup-2025-09-01.tgz /dest/path/backup-2025-09-01.tgz

# Import bundle to destination
python3 -m ai_proxy.logdb.cli bundle import ./backup-2025-09-01.tgz --dest ./logs/db
```

#### Database Merging

```bash
# Merge daily partitions into monthly database
./scripts/logdb merge --from ./logs/db/2025/09 --to ./logs/db/monthly/2025-09.sqlite3

# Verify merge integrity
./scripts/logdb merge --from ./logs/db/2025/09 --to ./logs/db/monthly/2025-09.sqlite3 | grep integrity
```

**Full commands:**

```bash
# Merge daily partitions into monthly database
python3 -m ai_proxy.logdb.cli merge --from ./logs/db/2025/09 --to ./logs/db/monthly/2025-09.sqlite3

# Verify merge integrity
python3 -m ai_proxy.logdb.cli merge --from ./logs/db/2025/09 --to ./logs/db/monthly/2025-09.sqlite3 | grep integrity
```

### Advanced Search Examples

#### Full-Text Search Queries

```sql
-- Natural language search
SELECT * FROM request_text_index
WHERE request_text_index MATCH 'machine learning';

-- Proximity search (words within 5 positions)
SELECT * FROM request_text_index
WHERE request_text_index MATCH 'error NEAR/5 timeout';

-- Boolean combinations
SELECT * FROM request_text_index
WHERE request_text_index MATCH '("machine learning" OR AI) AND python';

-- Search specific fields
SELECT * FROM request_text_index
WHERE role = 'user' AND request_text_index MATCH 'help';
```

#### Dialog Analysis

```sql
-- Find conversation patterns
SELECT dialog_id, COUNT(*) as message_count,
       MIN(ts) as start_time, MAX(ts) as end_time,
       api_key_hash
FROM requests
WHERE dialog_id IS NOT NULL
GROUP BY dialog_id
HAVING message_count > 5
ORDER BY start_time DESC;

-- Analyze model usage in conversations
SELECT dialog_id, model_original, COUNT(*) as usage_count
FROM requests
WHERE dialog_id IS NOT NULL
GROUP BY dialog_id, model_original
ORDER BY dialog_id, usage_count DESC;
```

#### Performance Analysis

```sql
-- Find slowest requests
SELECT request_id, endpoint, model_original,
       latency_ms, status_code,
       datetime(ts, 'unixepoch') as timestamp
FROM requests
ORDER BY latency_ms DESC
LIMIT 10;

-- Error rate analysis
SELECT model_original,
       COUNT(*) as total_requests,
       SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END) as errors,
       ROUND(100.0 * SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END) / COUNT(*), 2) as error_rate
FROM requests
GROUP BY model_original
ORDER BY error_rate DESC;
```

#### Multi-Partition Queries

```sql
-- Attach multiple partitions for cross-range analysis
ATTACH DATABASE 'logs/db/2025/09/ai_proxy_20250901.sqlite3' AS sept01;
ATTACH DATABASE 'logs/db/2025/09/ai_proxy_20250902.sqlite3' AS sept02;

-- Cross-partition analysis
SELECT COUNT(*) as total_requests,
       AVG(latency_ms) as avg_latency,
       MIN(ts) as earliest, MAX(ts) as latest
FROM (
    SELECT * FROM sept01.requests
    UNION ALL
    SELECT * FROM sept02.requests
);

DETACH DATABASE sept01;
DETACH DATABASE sept02;
```

### Production Integration Examples

#### Daily Log Processing Cron Job

```bash
#!/bin/bash
# /etc/cron.daily/process-ai-proxy-logs

cd /opt/ai-proxy

# Export configuration
export LOGDB_ENABLED=true
export LOGDB_FTS_ENABLED=true
export LOGDB_GROUPING_ENABLED=true

# Process yesterday's logs
YESTERDAY=$(date -d 'yesterday' +%Y-%m-%d)

# Ingest new logs
./scripts/logdb ingest --from ./logs --since $YESTERDAY --to $YESTERDAY

# Update FTS index
./scripts/logdb fts build --since $YESTERDAY --to $YESTERDAY

# Update dialog groups
./scripts/logdb dialogs assign --since $YESTERDAY --to $YESTERDAY

# Create weekly bundle (if it's Sunday)
if [ $(date +%u) -eq 7 ]; then
    WEEK_START=$(date -d 'last monday -6 days' +%Y-%m-%d)
    WEEK_END=$(date -d 'last sunday' +%Y-%m-%d)
    BUNDLE_NAME="weekly-$(date +%Y-%U).tgz"

    ./scripts/logdb bundle create \
        --since $WEEK_START \
        --to $WEEK_END \
        --out ./bundles/$BUNDLE_NAME

    # Verify bundle integrity
    if ./scripts/logdb bundle verify ./bundles/$BUNDLE_NAME; then
        echo "Weekly bundle created successfully: $BUNDLE_NAME"
    else
        echo "ERROR: Bundle verification failed!"
        exit 1
    fi
fi
```

#### Remote Backup Script

```bash
#!/bin/bash
# Backup logs to remote server

REMOTE_HOST="backup.example.com"
REMOTE_PATH="/var/backups/ai-proxy"

# Create bundle for last 7 days
START_DATE=$(date -d '7 days ago' +%Y-%m-%d)
END_DATE=$(date -d 'yesterday' +%Y-%m-%d)
BUNDLE_NAME="backup-$(date +%Y%m%d).tgz"

./scripts/logdb bundle create \
    --since $START_DATE \
    --to $END_DATE \
    --out ./tmp_$BUNDLE_NAME

# Transfer to remote server
./scripts/logdb bundle transfer \
    ./tmp_$BUNDLE_NAME \
    $REMOTE_HOST:$REMOTE_PATH/$BUNDLE_NAME

# Clean up local temporary file
rm ./tmp_$BUNDLE_NAME

# Verify remote bundle
ssh $REMOTE_HOST "cd /opt/ai-proxy && ./scripts/logdb bundle verify $REMOTE_PATH/$BUNDLE_NAME"
```

### Troubleshooting

#### Common Issues

**Ingestion fails with "database locked"**
```bash
# Check for long-running queries
sqlite3 logs/db/2025/09/ai_proxy_20250907.sqlite3 "SELECT * FROM sqlite_master WHERE type='table';"

# Force WAL checkpoint
sqlite3 logs/db/2025/09/ai_proxy_20250907.sqlite3 "PRAGMA wal_checkpoint(PASSIVE);"
```

**FTS search returns no results**
```bash
# Check if FTS table exists
sqlite3 logs/db/2025/09/ai_proxy_20250907.sqlite3 "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '%fts%';"

# Rebuild FTS index
poetry run python -m ai_proxy.logdb.cli fts drop --since 2025-09-07 --to 2025-09-07
poetry run python -m ai_proxy.logdb.cli fts build --since 2025-09-07 --to 2025-09-07
```

**Bundle verification fails**
```bash
# Check bundle contents
tar -tzf backup-2025-09-01.tgz | head -20

# Manual SHA256 verification
sha256sum logs/db/2025/09/ai_proxy_20250901.sqlite3
grep "ai_proxy_20250901.sqlite3" backup-2025-09-01.tgz.metadata.json
```

#### Performance Optimization

**Large dataset queries**
```sql
-- Use indexes effectively
EXPLAIN QUERY PLAN
SELECT * FROM requests
WHERE ts BETWEEN strftime('%s', '2025-09-01') AND strftime('%s', '2025-09-07')
  AND model_original LIKE 'gpt-4%'
ORDER BY ts DESC;

-- Consider covering indexes for common queries
CREATE INDEX idx_requests_covering ON requests(ts, model_original, latency_ms, status_code);
```

**Memory usage during ingestion**
```bash
# Monitor memory usage
LOGDB_MEMORY_CAP_MB=128 poetry run python -m ai_proxy.logdb.cli ingest --from ./logs --since 2025-09-01 --to 2025-09-07

# Use smaller batch sizes for memory-constrained environments
LOGDB_IMPORT_PARALLELISM=1 poetry run python -m ai_proxy.logdb.cli ingest --from ./logs --since 2025-09-01 --to 2025-09-07
```