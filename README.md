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
- Replace `YOUR-SERVER-IP` with your server's public IP address

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
