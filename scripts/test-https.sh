#!/bin/bash

# Test script for HTTPS functionality
set -e

# Load environment variables
if [ -f .env ]; then
    source .env
else
    echo "❌ .env file not found!"
    exit 1
fi

if [ -z "$DOMAIN" ]; then
    echo "❌ DOMAIN not set in .env file!"
    exit 1
fi

echo "🧪 Testing HTTPS setup for domain: $DOMAIN"
echo ""

# Test HTTP redirect to HTTPS
echo "1. 🔄 Testing HTTP to HTTPS redirect..."
HTTP_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" -L http://$DOMAIN/health || echo "000")
if [ "$HTTP_RESPONSE" = "200" ]; then
    echo "✅ HTTP redirect working"
else
    echo "❌ HTTP redirect failed (status: $HTTP_RESPONSE)"
fi

# Test HTTPS connection
echo ""
echo "2. 🔐 Testing HTTPS connection..."
HTTPS_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" https://$DOMAIN/health || echo "000")
if [ "$HTTPS_RESPONSE" = "200" ]; then
    echo "✅ HTTPS connection working"
else
    echo "❌ HTTPS connection failed (status: $HTTPS_RESPONSE)"
fi

# Test SSL certificate
echo ""
echo "3. 📜 Testing SSL certificate..."
CERT_INFO=$(curl -s -I https://$DOMAIN 2>&1 | grep -i "subject\|issuer" || echo "Certificate info not available")
if echo "$CERT_INFO" | grep -q "Let's Encrypt"; then
    echo "✅ Let's Encrypt certificate detected"
    echo "$CERT_INFO"
else
    echo "⚠️  Certificate info: $CERT_INFO"
fi

# Test API functionality
echo ""
echo "4. 🤖 Testing AI Proxy API..."
if [ ! -z "$API_KEYS" ]; then
    FIRST_KEY=$(echo $API_KEYS | cut -d',' -f1)
    API_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $FIRST_KEY" \
        -d '{"model":"gpt-4","messages":[{"role":"user","content":"test"}]}' \
        https://$DOMAIN/v1/chat/completions || echo "000")
    
    if [ "$API_RESPONSE" = "200" ] || [ "$API_RESPONSE" = "400" ] || [ "$API_RESPONSE" = "429" ]; then
        echo "✅ API endpoint accessible (status: $API_RESPONSE)"
    else
        echo "❌ API endpoint failed (status: $API_RESPONSE)"
    fi
else
    echo "⚠️  No API keys configured, skipping API test"
fi

# Test Traefik dashboard
echo ""
echo "5. 📊 Testing Traefik dashboard..."
DASHBOARD_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" https://traefik.$DOMAIN || echo "000")
if [ "$DASHBOARD_RESPONSE" = "200" ]; then
    echo "✅ Traefik dashboard accessible"
else
    echo "⚠️  Traefik dashboard not accessible (status: $DASHBOARD_RESPONSE)"
fi

echo ""
echo "🏁 Test completed!"
echo ""
echo "📋 Summary:"
echo "   - Domain: $DOMAIN"
echo "   - Main service: https://$DOMAIN"
echo "   - Traefik dashboard: https://traefik.$DOMAIN"
echo "   - Health check: https://$DOMAIN/health"
echo ""
echo "🔍 If tests failed, check:"
echo "   - docker-compose logs traefik"
echo "   - docker-compose logs ai-proxy"
echo "   - DNS configuration for $DOMAIN" 