# AI Proxy Cloud Development Environment
# Standalone Dockerfile for Docker-in-Docker support with Python, Poetry, and Node.js
# Designed for cloud deployment with mounted workspace

FROM ubuntu:22.04 AS base

# Install system dependencies and Docker
RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    gnupg \
    lsb-release \
    wget \
    && mkdir -p /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" > /etc/apt/sources.list.d/docker.list \
    && apt-get update && apt-get install -y \
    docker-ce \
    docker-ce-cli \
    containerd.io \
    docker-compose-plugin \
    curl \
    git \
    bash \
    sudo \
    openssh-client \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    nodejs \
    npm \
    jq \
    make \
    rsync \
    && ln -sf python3 /usr/bin/python

# Install Poetry
ENV POETRY_VERSION=2.1.4
ENV POETRY_HOME=/opt/poetry
ENV POETRY_VENV=/opt/poetry-venv
ENV POETRY_CACHE_DIR=/opt/.cache

RUN python3 -m venv $POETRY_VENV \
    && $POETRY_VENV/bin/pip install -U pip setuptools \
    && $POETRY_VENV/bin/pip install poetry==$POETRY_VERSION

# Create workspace user with Docker privileges
RUN groupadd -g 1000 workspace \
    && useradd -m -s /bin/bash -u 1000 -g workspace workspace \
    && echo 'workspace ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers \
    && usermod -aG docker workspace

# Configure Docker daemon for DinD
ENV DOCKER_TLS_CERTDIR=/certs
RUN mkdir -p /certs /certs/client \
    && chmod 755 /certs /certs/client \
    && mkdir -p /var/run \
    && chmod 755 /var/run

# Docker Compose is already installed via docker-compose-plugin

# Set up Python virtual environment and Poetry
ENV PATH="$POETRY_VENV/bin:$PATH"
ENV PYTHONPATH=/workspace

# Configure Poetry
RUN poetry config virtualenvs.create false \
    && poetry config virtualenvs.in-project false

# Install Python development tools using pip (before switching user)
RUN pip install \
    pytest \
    pytest-cov \
    pytest-asyncio \
    pytest-xdist \
    ruff \
    black \
    mypy \
    pre-commit \
    requests

# Skip Node.js global packages due to network issues
# They can be installed locally in the container if needed

# Create workspace directory
RUN mkdir -p /workspace \
    && chown -R workspace:workspace /workspace

# Switch to workspace user
USER workspace
WORKDIR /workspace

# Configure Poetry for development
RUN poetry config virtualenvs.create false

# Create entrypoint script
RUN echo '#!/bin/bash' > /home/workspace/entrypoint.sh && \
    echo 'set -e' >> /home/workspace/entrypoint.sh && \
    echo '' >> /home/workspace/entrypoint.sh && \
    echo '# Colors for output' >> /home/workspace/entrypoint.sh && \
    echo 'RED='\''\033[0;31m'\''' >> /home/workspace/entrypoint.sh && \
    echo 'GREEN='\''\033[0;32m'\''' >> /home/workspace/entrypoint.sh && \
    echo 'YELLOW='\''\033[1;33m'\''' >> /home/workspace/entrypoint.sh && \
    echo 'BLUE='\''\033[0;34m'\''' >> /home/workspace/entrypoint.sh && \
    echo 'NC='\''\033[0m'\''' >> /home/workspace/entrypoint.sh && \
    echo '' >> /home/workspace/entrypoint.sh && \
    echo 'log() {' >> /home/workspace/entrypoint.sh && \
    echo '    echo -e "${BLUE}[CLOUD-AGENT]${NC} $1"' >> /home/workspace/entrypoint.sh && \
    echo '}' >> /home/workspace/entrypoint.sh && \
    echo '' >> /home/workspace/entrypoint.sh && \
    echo 'success() {' >> /home/workspace/entrypoint.sh && \
    echo '    echo -e "${GREEN}✅ [CLOUD-AGENT]${NC} $1"' >> /home/workspace/entrypoint.sh && \
    echo '}' >> /home/workspace/entrypoint.sh && \
    echo '' >> /home/workspace/entrypoint.sh && \
    echo 'warning() {' >> /home/workspace/entrypoint.sh && \
    echo '    echo -e "${YELLOW}⚠️  [CLOUD-AGENT]${NC} $1"' >> /home/workspace/entrypoint.sh && \
    echo '}' >> /home/workspace/entrypoint.sh && \
    echo '' >> /home/workspace/entrypoint.sh && \
    echo 'error() {' >> /home/workspace/entrypoint.sh && \
    echo '    echo -e "${RED}❌ [CLOUD-AGENT]${NC} $1"' >> /home/workspace/entrypoint.sh && \
    echo '}' >> /home/workspace/entrypoint.sh && \
    echo '' >> /home/workspace/entrypoint.sh && \
    echo 'log "Starting Cloud Agent Environment..."' >> /home/workspace/entrypoint.sh && \
    echo 'success "Python + Poetry ready"' >> /home/workspace/entrypoint.sh && \
    echo 'success "Node.js + npm ready"' >> /home/workspace/entrypoint.sh && \
    echo '' >> /home/workspace/entrypoint.sh && \
    echo '# Start internal Docker daemon' >> /home/workspace/entrypoint.sh && \
    echo 'log "Starting internal Docker daemon..."' >> /home/workspace/entrypoint.sh && \
    echo 'sudo dockerd --host=unix:///var/run/docker.sock --host=tcp://0.0.0.0:2376 --tls=false &' >> /home/workspace/entrypoint.sh && \
    echo '# Wait for Docker to start (up to 30 seconds)' >> /home/workspace/entrypoint.sh && \
    echo 'for i in {1..30}; do' >> /home/workspace/entrypoint.sh && \
    echo '    if docker version >/dev/null 2>&1; then' >> /home/workspace/entrypoint.sh && \
    echo '        success "Internal Docker daemon started"' >> /home/workspace/entrypoint.sh && \
    echo '        break' >> /home/workspace/entrypoint.sh && \
    echo '    fi' >> /home/workspace/entrypoint.sh && \
    echo '    sleep 1' >> /home/workspace/entrypoint.sh && \
    echo 'done' >> /home/workspace/entrypoint.sh && \
    echo 'if ! docker version >/dev/null 2>&1; then' >> /home/workspace/entrypoint.sh && \
    echo '    error "Failed to start internal Docker daemon"' >> /home/workspace/entrypoint.sh && \
    echo '    exit 1' >> /home/workspace/entrypoint.sh && \
    echo 'fi' >> /home/workspace/entrypoint.sh && \
    echo '' >> /home/workspace/entrypoint.sh && \
    echo '# Check if workspace is mounted' >> /home/workspace/entrypoint.sh && \
    echo 'if [ -f "/workspace/pyproject.toml" ]; then' >> /home/workspace/entrypoint.sh && \
    echo '    success "Project workspace mounted successfully"' >> /home/workspace/entrypoint.sh && \
    echo '    log "Available commands:"' >> /home/workspace/entrypoint.sh && \
    echo '    log "  make help          - Show all available commands"' >> /home/workspace/entrypoint.sh && \
    echo '    log "  make install       - Install dependencies"' >> /home/workspace/entrypoint.sh && \
    echo '    log "  make test          - Run all tests"' >> /home/workspace/entrypoint.sh && \
    echo '    log "  make dev           - Start development server"' >> /home/workspace/entrypoint.sh && \
    echo '    log "  docker version     - Check Docker status"' >> /home/workspace/entrypoint.sh && \
    echo 'else' >> /home/workspace/entrypoint.sh && \
    echo '    warning "Project workspace not mounted or pyproject.toml not found"' >> /home/workspace/entrypoint.sh && \
    echo '    log "Mount your project to /workspace to get started"' >> /home/workspace/entrypoint.sh && \
    echo 'fi' >> /home/workspace/entrypoint.sh && \
    echo '' >> /home/workspace/entrypoint.sh && \
    echo '# Execute the command or start interactive shell' >> /home/workspace/entrypoint.sh && \
    echo 'if [ $# -eq 0 ]; then' >> /home/workspace/entrypoint.sh && \
    echo '    success "Starting interactive shell..."' >> /home/workspace/entrypoint.sh && \
    echo '    exec /bin/bash' >> /home/workspace/entrypoint.sh && \
    echo 'else' >> /home/workspace/entrypoint.sh && \
    echo '    exec "$@"' >> /home/workspace/entrypoint.sh && \
    echo 'fi' >> /home/workspace/entrypoint.sh

RUN chmod +x /home/workspace/entrypoint.sh

# Add Poetry to PATH
ENV PATH="/home/workspace/.local/bin:$PATH"

# Set environment variables for development
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV NODE_ENV=development
ENV DOCKER_CONTAINER=true

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD docker version || exit 1

# Expose ports for development
EXPOSE 8123 8124 5173 2376

# Set entrypoint
ENTRYPOINT ["/home/workspace/entrypoint.sh"]

# Default command - start interactive shell
CMD []


#some extra line for fun
