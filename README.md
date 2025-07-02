# AI Proxy Service

This service acts as a drop-in replacement for the OpenAI API, providing a unified interface to route requests to various Large Language Model (LLM) providers like OpenRouter.

It is built with Python and FastAPI and is designed to be lightweight, fast, and easy to deploy with **HTTPS support** and automatic SSL certificate management.

## Features (Phase 1)

*   **OpenAI API Compatibility**: `POST /v1/chat/completions` endpoint.
*   **Provider Routing**: Currently supports proxying requests to [OpenRouter](https://openrouter.ai/) and **Google Gemini API**.
*   **Model Mapping**: Configure model aliases or use wildcards to map friendly names to specific provider models (e.g., `gpt-4` -> `openai/gpt-4`, `gemini-pro` -> `gemini:gemini-1.5-pro-latest`).
*   **Authentication**: Secure the proxy with API keys.
*   **HTTPS Support**: Automatic SSL certificate management with Let's Encrypt via Traefik.
*   **Structured Logging**: JSON-formatted logs for easy parsing and monitoring.
*   **Containerized**: Ready to deploy with Docker and Docker Compose.

## Getting Started

### Prerequisites

*   Python 3.10+
*   [Poetry](https://python-poetry.org/) for dependency management.
*   Docker and Docker Compose (for containerized deployment).
*   A domain name (for HTTPS in production).
*   `google-genai` (installed automatically with Poetry for Gemini support)

### Quick HTTPS Setup (Recommended)

1.  **Clone the repository:**
    ```bash
    git clone <repository-url>
    cd ai-proxy
    ```

2.  **Run the HTTPS setup script:**
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
    GEMINI_API_KEY=your-gemini-api-key # Required for Gemini API support

    # Optional: Custom Port Configuration
    # Uncomment and set if you need non-standard HTTP/HTTPS ports
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
- **AI Proxy**: `https://your-domain.com` (or `http://your-domain.com` for HTTP, if not redirected)
- **Traefik Dashboard**: `https://traefik.your-domain.com`

### Domain Options

#### 🆓 Free Temporary Domains (for testing)
- **nip.io**: Set `DOMAIN=myapp.YOUR-SERVER-IP.nip.io`
- **sslip.io**: Set `DOMAIN=myapp.YOUR-SERVER-IP.sslip.io`
- Replace `YOUR-SERVER-IP` with your server's public IP address. You can get your server's public IPv4 address by running: `curl -4 ifconfig.me` on the server.

#### 🌍 Real Domain (recommended for production)
- Buy a domain from any registrar (Namecheap, GoDaddy, etc.)
- Point A record to your server's IP
- Set `DOMAIN=your-domain.com`

#### 🧪 Development with ngrok
- Install [ngrok](https://ngrok.com/)
- Run: `ngrok http 80`
- Use the ngrok domain in your `DOMAIN` variable

### Local Development (HTTP)

1.  **Install dependencies:**
    ```bash
    poetry install
    ```

2.  **Set up environment variables:**
    ```bash
    cp .env.example .env
    # Edit .env with your configuration, including optional HTTP_PORT if needed
    ```

3.  **Run the service:**
    ```bash
    poetry run uvicorn ai_proxy.main:app --reload
    ```
    The service will be available at `http://localhost:8123` (or your custom HTTP_PORT if configured).

### Docker Deployment (HTTP only)

1.  **Build the Docker image:**
    ```bash
    docker build -t ai-proxy .
    ```

2.  **Run the Docker container:**
    ```bash
    docker run -d --env-file .env -p 8123:8123 --name ai-proxy-container ai-proxy
    ```

## Usage

Make requests to the proxy service just as you would with the OpenAI API:

### HTTPS (Production)
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

### HTTP (Development)
```bash
curl http://localhost:8123/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-secret-key-1" \
  -d '{
    "model": "gemini-pro", # Example: Using a Gemini model
    "messages": [
      {
        "role": "user",
        "content": "What is the capital of France?"
      }
    ]
  }'
```

The `model` field will be automatically mapped according to your `config.yml`. For example:

- If `config.yml` has `"gpt-4": "openrouter:openai/gpt-4"`, the request will be sent to OpenRouter with `openai/gpt-4`.
- If `config.yml` has `"gemini-pro": "gemini:gemini-1.5-pro-latest"`, the request will be sent to Gemini with `gemini-1.5-pro-latest`.
- You can explicitly specify the provider: `"model": "openrouter:mistralai/mistral-small"` or `"model": "gemini:gemini-1.5-flash-latest"`.

## Production Testing

To test your production deployment, you can use these commands that automatically detect your domain and API keys from the `.env` file:

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

## HTTPS Configuration

The service uses **Traefik** as a reverse proxy with automatic **Let's Encrypt** SSL certificate management. This provides:

- ✅ Automatic SSL certificate generation and renewal
- ✅ HTTP to HTTPS redirect
- ✅ Security headers (HSTS, etc.)
- ✅ Load balancing capabilities
- ✅ Monitoring dashboard

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
    ```bash
    # Example: Stop a container named 'another-service'
    docker stop another-service
    ```
2.  **Reconfigure** your `.env` file to use standard ports (80 and 443):
    ```env
    HTTP_PORT=80
    HTTPS_PORT=443
    ```
3.  **Deploy** the AI Proxy service. Traefik will now be able to obtain the Let's Encrypt certificate.
    ```bash
    docker-compose up -d
    ```
4.  **Verify** certificate acquisition (check Traefik logs).
5.  **Reconfigure** your `.env` file back to your desired custom ports (e.g., 9080 and 9443).
    ```env
    HTTP_PORT=9080
    HTTPS_PORT=9443
    ```
6.  **Redeploy** the AI Proxy service on custom ports.
    ```bash
    docker-compose up -d
    ```
7.  **Restart** the original service(s) that were temporarily stopped.
    ```bash
    # Example: Start 'another-service' back
    docker start another-service
    ```

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

## Security Features

- 🔐 **API Key Authentication**: Secure access control
- 🛡️ **HTTPS Encryption**: All traffic encrypted in transit
- 🔒 **Security Headers**: HSTS, secure redirects
- 📊 **Request Logging**: Comprehensive audit trail
- 🚫 **Rate Limiting**: Built-in protection (via Traefik)

## Monitoring

- **Health Check**: `https://your-domain.com/health`
- **Traefik Dashboard**: `https://traefik.your-domain.com`
- **Logs**: Structured JSON logs in `logs/` directory
