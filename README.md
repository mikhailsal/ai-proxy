# AI Proxy Service

This service acts as a drop-in replacement for the OpenAI API, providing a unified interface to route requests to various Large Language Model (LLM) providers like OpenRouter and Google Gemini.

It is built with Python and FastAPI and is designed to be lightweight, fast, and easy to deploy with **HTTPS support** and automatic SSL certificate management.

## Features

*   **OpenAI API Compatibility**: `POST /v1/chat/completions` endpoint.
*   **Provider Routing**: Currently supports proxying requests to [OpenRouter](https://openrouter.ai/) and **Google Gemini API**.
*   **Model Mapping**: Configure model aliases or use wildcards to map friendly names to specific provider models (e.g., `gpt-4` -> `openai/gpt-4`, `gemini-pro` -> `gemini:gemini-1.5-pro-latest`).
*   **Authentication**: Secure the proxy with API keys.
*   **HTTPS Support**: Automatic SSL certificate management with Let's Encrypt via Traefik.
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
