## Advanced Log Storage System

The AI Proxy features a SQLite log storage system that transforms text logs into a searchable database, designed for production with incremental processing, full-text search, dialog grouping, and portable bundles.

### Core Features

*   **SQLite Storage**: Efficient partitioned database with WAL mode
*   **Full-Text Search**: FTS5 virtual tables for natural language queries
*   **Dialog Grouping**: Automatic grouping by time and API keys
*   **Portable Bundles**: Compressed archives with integrity checks
*   **Incremental Processing**: Safe log ingestion from checkpoints
*   **Multi-Server Support**: Identity management and deduplication

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

#### Wrapper global flags and environment precedence

- The wrapper auto-loads variables from `.env` before running commands.
- Already-exported environment variables always take precedence over `.env` values.
- To disable auto-loading `.env`, pass a global flag before the command: `--no-dotenv`.

Examples:

```bash
# Use .env values automatically
./scripts/logdb ingest --from ./logs --since 2025-09-01 --to 2025-09-07

# Explicitly override a value just for this invocation
LOGDB_IMPORT_PARALLELISM=4 ./scripts/logdb ingest --from ./logs --since 2025-09-01 --to 2025-09-07

# Run without loading .env (only current environment is used)
./scripts/logdb --no-dotenv ingest --from ./logs --since 2025-09-01 --to 2025-09-07
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

### Logs UI: DB volume and permissions for local runs

The Logs UI API reads SQLite partitions from a mounted directory. For local development:

- Ensure `logs-ui-api` service mounts the DB directory read-only and runs as your host user:

```yaml
services:
  logs-ui-api:
    user: "${HOST_UID:-1000}:${HOST_GID:-1000}"
    volumes:
      - ./logs/db:/app/logs/db:ro
```

- Export your host UID/GID when starting services so the container uses matching permissions:

```bash
export HOST_UID=$(id -u)
export HOST_GID=$(id -g)
docker compose up -d logs-ui-api logs-ui-web
```

- Ingestion writes should be performed on the host (or via a one-off write-capable helper container), not from the read-only API container. If you encounter permission issues on an existing DB path, you can fix ownership/permissions safely with a temporary container:

```bash
docker run --rm -v $(PWD)/logs/db:/work alpine sh -c "chown -R $(id -u):$(id -g) /work || true; chmod -R u+rwX /work || true"
```

---

## Troubleshooting and Examples

### Hot Reload Not Working

**Problem:** Changes to `ui/src/` files don't trigger browser reload.

**Solutions:**

1. Check if Vite dev server is running:
   ```bash
   docker compose -f docker-compose.dev.yml logs logs-ui-web
   ```

2. Verify file watching is enabled:
   ```bash
   docker compose -f docker-compose.dev.yml exec logs-ui-web cat /app/vite.config.ts
   ```

3. Restart dev container:
   ```bash
   make dev-restart
   ```

### Port Conflicts

**Problem:** Error "port 5173 is already allocated"

**Solution:**

```bash
# Check what's using port 5173
sudo lsof -i :5173

# Stop conflicting container
docker ps | grep 5173
docker stop <container-id>

# Or change port in docker-compose.dev.yml
```

### Testing

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

### Advanced Examples

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

... (full CLI, bundle operations, merging, and SQL examples retained)
