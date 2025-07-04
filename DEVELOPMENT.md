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

The project includes a safe production deployment script that preserves production-specific files while updating code:

```bash
# Deploy latest changes to production
DEPLOY_HOST=your-server ./scripts/deploy-production.sh

# Rollback to previous version
DEPLOY_HOST=your-server ./scripts/deploy-production.sh --rollback
```

### What the script does:

**Safety Features:**
- ✅ Creates automatic backup before deployment
- ✅ Preserves SSL certificates (`certs/` directory)
- ✅ Preserves environment configuration (`.env` files)
- ✅ Preserves production logs (`logs/` directory)
- ✅ Preserves Traefik configuration (`traefik/` directory)
- ✅ Only syncs specific code files (never deletes production configs)

**Deployment Process:**
- ✅ Health check before deployment
- ✅ Creates timestamped backup
- ✅ Syncs only changed code files
- ✅ Rebuilds and restarts containers
- ✅ Verifies deployment with health checks
- ✅ Tests basic functionality
- ✅ Cleans up old backups (keeps last 5)

**Environment Variables:**
- `DEPLOY_HOST` - Target server hostname (required)
- `DEPLOY_PATH` - Remote deployment path (default: `/root/ai-proxy`)

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

The service uses **Traefik** as a reverse proxy with automatic **Let's Encrypt** SSL certificate management.

### Custom Port Configuration

By default, the service uses standard HTTP (80) and HTTPS (443) ports. You can customize these by setting the `HTTP_PORT` and `HTTPS_PORT` variables in your `.env` file:

```env
HTTP_PORT=9080  # Example: Change HTTP to 9080
HTTPS_PORT=9443 # Example: Change HTTPS to 9443
```

Ensure these ports are open on your server's firewall and do not conflict with other services.

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
├── scripts/                # Setup and testing scripts
│   ├── setup-https.sh     # HTTPS configuration script
│   └── test-https.sh      # HTTPS testing script
├── docker-compose.yml     # Production deployment with HTTPS
├── Dockerfile             # Application container
├── .env.example          # Environment configuration template
└── README.md             # This file
```