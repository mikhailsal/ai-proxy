#!/bin/bash

# Setup script for HTTPS configuration
set -e

echo "🔐 Setting up HTTPS for AI Proxy Service"

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p traefik certs logs

# Set proper permissions for certificate storage
echo "🔑 Setting certificate directory permissions..."
chmod 755 certs
touch certs/acme.json
chmod 600 certs/acme.json

# Check if .env file exists
if [ ! -f .env ]; then
    echo "⚠️  .env file not found. Creating from template..."
    cp .env.example .env
    echo "✏️  Please edit .env file with your configuration:"
    echo "   - DOMAIN: Your domain name"
    echo "   - ACME_EMAIL: Your email for Let's Encrypt"
    echo "   - API_KEYS: Your API keys"
    echo "   - OPENROUTER_API_KEY: Your OpenRouter key"
else
    echo "✅ .env file found"
fi

# Check if domain is configured
source .env 2>/dev/null || true
if [ -z "$DOMAIN" ] || [ "$DOMAIN" = "your-domain.com" ]; then
    echo ""
    echo "🌐 Domain Configuration Options:"
    echo ""
    echo "1. 🆓 Free temporary domains (for testing):"
    echo "   - Use nip.io: Set DOMAIN to something like 'myapp.192.168.1.100.nip.io'"
    echo "   - Use sslip.io: Set DOMAIN to something like 'myapp.192.168.1.100.sslip.io'"
    echo "   - Replace 192.168.1.100 with your server's public IP"
    echo ""
    echo "2. 🌍 Real domain (recommended for production):"
    echo "   - Buy a domain from any registrar"
    echo "   - Point A record to your server's IP"
    echo "   - Set DOMAIN to your domain name"
    echo ""
    echo "3. 🧪 Development with ngrok:"
    echo "   - Install ngrok: https://ngrok.com/"
    echo "   - Run: ngrok http 80"
    echo "   - Use the ngrok domain in DOMAIN variable"
    echo ""
    echo "⚠️  Remember: Let's Encrypt requires your domain to be publicly accessible!"
fi

echo ""
echo "🚀 Setup complete! Next steps:"
echo "1. Configure your domain in .env file"
echo "2. Update DNS records to point to this server"
echo "3. Run: docker-compose up -d"
echo "4. Check logs: docker-compose logs -f"
echo ""
echo "🌐 Your services will be available at:"
echo "   - AI Proxy: https://\$DOMAIN"
echo "   - Traefik Dashboard: https://traefik.\$DOMAIN"
echo ""
echo "🔍 Troubleshooting:"
echo "   - Check certificate status: docker-compose logs traefik"
echo "   - Verify domain accessibility: curl -I http://\$DOMAIN"
echo "   - Test HTTPS: curl -I https://\$DOMAIN" 