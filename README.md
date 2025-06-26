# AI Proxy Service

This service acts as a drop-in replacement for the OpenAI API, providing a unified interface to route requests to various Large Language Model (LLM) providers like OpenRouter.

It is built with Python and FastAPI and is designed to be lightweight, fast, and easy to deploy.

## Features (Phase 1)

*   **OpenAI API Compatibility**: `POST /v1/chat/completions` endpoint.
*   **Provider Routing**: Currently supports proxying requests to [OpenRouter](https://openrouter.ai/).
*   **Model Mapping**: Configure model aliases or use wildcards to map friendly names to specific provider models (e.g., `gpt-4` -> `openai/gpt-4`).
*   **Authentication**: Secure the proxy with API keys.
*   **Structured Logging**: JSON-formatted logs for easy parsing and monitoring.
*   **Containerized**: Ready to deploy with Docker.

## Getting Started

### Prerequisites

*   Python 3.10+
*   [Poetry](https://python-poetry.org/) for dependency management.
*   Docker (for containerized deployment).

### Local Development

1.  **Clone the repository:**
    ```bash
    git clone <repository-url>
    cd ai-proxy
    ```

2.  **Install dependencies:**
    ```bash
    poetry install
    ```

3.  **Set up environment variables:**
    Copy the example `.env.example` file to `.env` and fill in your details.
    ```bash
    cp .env.example .env
    ```
    You will need to provide:
    *   `API_KEYS`: A comma-separated list of keys to access this proxy service.
    *   `OPENROUTER_API_KEY`: Your key for the OpenRouter service.

4.  **Configure Model Mappings (Optional):**
    Edit the `config.yml` file to define your model aliases and wildcard mappings.

5.  **Run the service:**
    ```bash
    poetry run uvicorn ai_proxy.main:app --reload
    ```
    The service will be available at `http://localhost:8123`.

### Docker Deployment

1.  **Build the Docker image:**
    ```bash
    docker build -t ai-proxy .
    ```

2.  **Run the Docker container:**
    Make sure you have a `.env` file with your credentials in the same directory.
    ```bash
    docker run -d --env-file .env -p 8123:8123 --name ai-proxy-container ai-proxy
    ```

## Usage

Make requests to the proxy service just as you would with the OpenAI API, but use the service's URL and one of your defined `API_KEYS`.

```bash
curl http://localhost:8123/v1/chat/completions \
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

The `model` field will be automatically mapped according to your `config.yml`. For example, if you have `"gpt-4": "openai/gpt-4"` in your config, the request will be sent to OpenRouter with the model `openai/gpt-4`. 