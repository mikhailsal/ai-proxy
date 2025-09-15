#!/bin/bash

# AI Proxy Environment Setup Script
# This script installs all dependencies required for running tests and development

set -e

echo "🚀 Starting AI Proxy environment setup..."

# Install Poetry if not already installed
if ! command -v poetry &> /dev/null; then
    echo "📦 Installing Poetry..."
    curl -sSL https://install.python-poetry.org | python3 -
    export PATH="$HOME/.local/bin:$PATH"
else
    echo "✅ Poetry already installed"
fi

# Add Poetry to PATH for current session
export PATH="$HOME/.local/bin:$PATH"

# Navigate to project directory
cd /workspace

# Install Python dependencies
echo "🐍 Installing Python dependencies..."
poetry install --with dev

# Install Docker and Docker Compose if not present
if ! command -v docker &> /dev/null; then
    echo "🐳 Installing Docker..."
    sudo apt update
    sudo apt install -y docker.io docker-compose
else
    echo "✅ Docker already installed"
fi

# Start Docker daemon if not running
if ! pgrep -f dockerd > /dev/null; then
    echo "🔄 Starting Docker daemon..."
    sudo dockerd --host unix:///var/run/docker.sock --host tcp://0.0.0.0:2376 &
    sleep 3
else
    echo "✅ Docker daemon already running"
fi

# Verify installations
echo "🔍 Verifying installations..."
echo "Python version: $(python3 --version)"
echo "Poetry version: $(poetry --version)"
echo "Docker version: $(docker --version)"
echo "Docker Compose version: $(docker-compose --version)"

# Run a quick test to ensure everything works
echo "🧪 Running quick test verification..."
poetry run pytest tests/unit/test_main.py::TestMainApp::test_app_creation -v

echo "🎉 Environment setup complete!"
echo ""
echo "To run tests:"
echo "  make test-unit          # Run unit tests"
echo "  make test-integration   # Run integration tests"
echo "  make test               # Run all tests"
echo ""
echo "To run the application:"
echo "  poetry run uvicorn ai_proxy.main:app --reload"
echo ""
echo "Happy coding! 🤖"