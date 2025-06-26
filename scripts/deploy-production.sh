#!/bin/bash

# Production deployment script with HTTPS
set -e

echo "🚀 Deploying AI Proxy Service to Production"

# Check if running as root or with sudo
if [ "$EUID" -eq 0 ]; then
    echo "⚠️  Running as root. Make sure Docker is properly configured."
fi

# Check if Docker and Docker Compose are installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

# Run HTTPS setup
echo "🔐 Setting up HTTPS configuration..."
./scripts/setup-https.sh

# Check if .env is properly configured
source .env
if [ -z "$DOMAIN" ] || [ "$DOMAIN" = "your-domain.com" ]; then
    echo "❌ Please configure DOMAIN in .env file before deployment!"
    echo "Edit .env and set your domain name."
    exit 1
fi

if [ -z "$ACME_EMAIL" ] || [ "$ACME_EMAIL" = "your-email@example.com" ]; then
    echo "❌ Please configure ACME_EMAIL in .env file before deployment!"
    echo "Edit .env and set your email for Let's Encrypt."
    exit 1
fi

if [ -z "$API_KEYS" ] || [ "$API_KEYS" = "your-secret-key-1,your-secret-key-2" ]; then
    echo "❌ Please configure API_KEYS in .env file before deployment!"
    echo "Edit .env and set your API keys."
    exit 1
fi

if [ -z "$OPENROUTER_API_KEY" ] || [ "$OPENROUTER_API_KEY" = "your-openrouter-api-key" ]; then
    echo "❌ Please configure OPENROUTER_API_KEY in .env file before deployment!"
    echo "Edit .env and set your OpenRouter API key."
    exit 1
fi

echo "✅ Configuration validated"

# Stop any existing containers
echo "🛑 Stopping existing containers..."
docker-compose down --remove-orphans || true

# Pull latest images
echo "📥 Pulling latest images..."
docker-compose pull

# Build application image
echo "🔨 Building application image..."
docker-compose build ai-proxy

# Start services
echo "🚀 Starting services..."
docker-compose up -d

# Wait for services to start
echo "⏳ Waiting for services to start..."
sleep 10

# Check service status
echo "🔍 Checking service status..."
docker-compose ps

# Test the deployment
echo "🧪 Testing deployment..."
sleep 5
./scripts/test-https.sh

echo ""
echo "🎉 Production deployment completed!"
echo ""
echo "📋 Service URLs:"
echo "   - AI Proxy: https://$DOMAIN"
echo "   - Traefik Dashboard: https://traefik.$DOMAIN"
echo "   - Health Check: https://$DOMAIN/health"
echo ""
echo "📊 Monitoring commands:"
echo "   - View logs: docker-compose logs -f"
echo "   - Check status: docker-compose ps"
echo "   - Stop services: docker-compose down"
echo "   - Restart: docker-compose restart"
echo ""
echo "🔧 Maintenance:"
echo "   - Certificates auto-renew via Let's Encrypt"
echo "   - Logs rotate automatically"
echo "   - Update with: git pull && ./scripts/deploy-production.sh" 