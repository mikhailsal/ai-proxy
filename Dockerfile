FROM python:3.11-slim

# Install system dependencies including sudo for permission fixes
RUN apt-get update && apt-get install -y \
    curl \
    sudo \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Install poetry
RUN pip install poetry

# Configure poetry to not create virtual environment (we're in a container)
ENV POETRY_VENV_IN_PROJECT=false
ENV POETRY_VIRTUALENVS_CREATE=false

# Copy project files
COPY poetry.lock pyproject.toml ./

# Install dependencies (including dev for testing)
RUN poetry install --no-root

# Copy application source code
COPY ./ai_proxy ./ai_proxy
COPY ./ai_proxy_ui ./ai_proxy_ui
COPY ./config.yml ./config.yml

# Copy setup scripts (used by docker-compose)
COPY ./scripts/ensure-deployment-timestamp.sh ./scripts/ensure-deployment-timestamp.sh
COPY ./scripts/container-entrypoint.sh ./scripts/container-entrypoint.sh
RUN chmod +x ./scripts/ensure-deployment-timestamp.sh ./scripts/container-entrypoint.sh

# Create directories with proper permissions
RUN mkdir -p /app/logs /app/certs /app/traefik /app/bundles /app/tmp

# Expose port and run application
EXPOSE 8123
CMD ["./scripts/container-entrypoint.sh", "./scripts/ensure-deployment-timestamp.sh", "uvicorn", "ai_proxy.main:app", "--host", "0.0.0.0", "--port", "8123"]
