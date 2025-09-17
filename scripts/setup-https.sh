#!/bin/bash

# Setup script for HTTPS configuration with automatic domain detection (non-interactive)
set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Default values
DEFAULT_SERVICE="nip.io"
DEFAULT_EMAIL="info@techsupport-services.com"
DEFAULT_SUBDOMAIN="ai-proxy"

# Parse command line arguments
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Setup HTTPS configuration with automatic domain detection.

OPTIONS:
    -s, --service SERVICE    Domain service: nip.io, sslip.io, ngrok, custom (default: nip.io)
    -d, --domain DOMAIN      Custom domain (required if service=custom or ngrok)
    -e, --email EMAIL        Email for Let's Encrypt (default: info@techsupport-services.com)
    -n, --name NAME          Subdomain name (default: ai-proxy)
    -h, --help               Show this help message

EXAMPLES:
    $0                                          # Use defaults (nip.io)
    $0 -s sslip.io                             # Use sslip.io service
    $0 -s custom -d api.example.com            # Use custom domain
    $0 -s ngrok -d abc123.ngrok.io             # Use ngrok domain
    $0 -e user@example.com -n myapp            # Custom email and subdomain

EOF
}

# Parse arguments
DOMAIN_SERVICE="$DEFAULT_SERVICE"
CUSTOM_DOMAIN=""
ACME_EMAIL="$DEFAULT_EMAIL"
SUBDOMAIN="$DEFAULT_SUBDOMAIN"

while [[ $# -gt 0 ]]; do
    case $1 in
        -s|--service)
            DOMAIN_SERVICE="$2"
            shift 2
            ;;
        -d|--domain)
            CUSTOM_DOMAIN="$2"
            shift 2
            ;;
        -e|--email)
            ACME_EMAIL="$2"
            shift 2
            ;;
        -n|--name)
            SUBDOMAIN="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo -e "${RED}❌ Unknown option: $1${NC}"
            usage
            exit 1
            ;;
    esac
done

echo -e "${BLUE}🔐 Setting up HTTPS for AI Proxy Service${NC}"
echo -e "${BLUE}Service: $DOMAIN_SERVICE, Email: $ACME_EMAIL, Subdomain: $SUBDOMAIN${NC}"

# Create necessary directories
echo -e "${BLUE}📁 Creating directories...${NC}"
mkdir -p traefik certs logs

# Set proper permissions for certificate storage
echo -e "${BLUE}🔑 Setting certificate directory permissions...${NC}"
chmod 755 certs
touch certs/acme.json
chmod 600 certs/acme.json

# Function to detect public IP
detect_public_ip() {
    echo -e "${BLUE}🌍 Detecting public IP address...${NC}" >&2

    # Try multiple IP detection services
    local ip=""
    local services=(
        "curl -s --max-time 5 https://ifconfig.me"
        "curl -s --max-time 5 https://ipinfo.io/ip"
        "curl -s --max-time 5 https://icanhazip.com"
        "curl -s --max-time 5 https://ident.me"
    )

    for service in "${services[@]}"; do
        if ip=$(eval "$service" 2>/dev/null | tr -d '\n' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'); then
            if [ -n "$ip" ]; then
                echo -e "${GREEN}✅ Detected public IP: $ip${NC}" >&2
                echo "$ip"
                return 0
            fi
        fi
    done

    # Try dig as fallback
    if command -v dig >/dev/null 2>&1; then
        if ip=$(dig +short myip.opendns.com @resolver1.opendns.com 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'); then
            if [ -n "$ip" ]; then
                echo -e "${GREEN}✅ Detected public IP via dig: $ip${NC}" >&2
                echo "$ip"
                return 0
            fi
        fi
    fi

    echo -e "${RED}❌ Could not detect public IP automatically${NC}" >&2
    return 1
}

# Function to generate domain based on service
generate_domain() {
    local public_ip="$1"
    local service="$2"

    case "$service" in
        "nip.io")
            echo "$SUBDOMAIN.$public_ip.nip.io"
            ;;
        "sslip.io")
            echo "$SUBDOMAIN.$public_ip.sslip.io"
            ;;
        "ngrok"|"custom")
            if [ -z "$CUSTOM_DOMAIN" ]; then
                echo -e "${RED}❌ Custom domain required for service: $service${NC}"
                echo -e "${RED}Use: $0 -s $service -d your-domain.com${NC}"
                return 1
            fi
            echo "$CUSTOM_DOMAIN"
            ;;
        *)
            echo -e "${RED}❌ Unknown service: $service${NC}"
            echo -e "${RED}Supported services: nip.io, sslip.io, ngrok, custom${NC}"
            return 1
            ;;
    esac
}

# Function to update .env file
update_env_file() {
    local domain="$1"
    local email="$2"

    # Check if .env file exists
    if [ ! -f .env ]; then
        echo -e "${YELLOW}⚠️  .env file not found. Creating from template...${NC}"
        if [ -f .env.example ]; then
            cp .env.example .env
        else
            # Create minimal .env if no template exists - ONLY with HTTPS settings
            cat > .env << EOF
# AI Proxy HTTPS Configuration
DOMAIN=$domain
ACME_EMAIL=$email

# Note: Add your API keys here:
# API_KEYS=your-secret-key-here
# OPENROUTER_API_KEY=your-openrouter-key-here
# GEMINI_API_KEY=your-gemini-key-here
EOF
        fi
    fi

    # Update ONLY domain and email fields, preserve everything else
    # Update domain in .env file using grep and temporary file approach
    if grep -q "^DOMAIN=" .env; then
        # Update existing DOMAIN line
        grep -v "^DOMAIN=" .env > .env.tmp
        echo "DOMAIN=$domain" >> .env.tmp
        mv .env.tmp .env
    else
        # Add DOMAIN line
        echo "DOMAIN=$domain" >> .env
    fi

    # Update or add ACME_EMAIL
    if grep -q "^ACME_EMAIL=" .env; then
        # Update existing ACME_EMAIL line
        grep -v "^ACME_EMAIL=" .env > .env.tmp
        echo "ACME_EMAIL=$email" >> .env.tmp
        mv .env.tmp .env
    else
        echo "ACME_EMAIL=$email" >> .env
    fi

    # Enforce production ports (80/443) for Let's Encrypt HTTP/ALPN challenges
    if grep -q "^HTTP_PORT=" .env; then
        grep -v "^HTTP_PORT=" .env > .env.tmp
        echo "HTTP_PORT=80" >> .env.tmp
        mv .env.tmp .env
    else
        echo "HTTP_PORT=80" >> .env
    fi
    if grep -q "^HTTPS_PORT=" .env; then
        grep -v "^HTTPS_PORT=" .env > .env.tmp
        echo "HTTPS_PORT=443" >> .env.tmp
        mv .env.tmp .env
    else
        echo "HTTPS_PORT=443" >> .env
    fi

    echo -e "${GREEN}✅ Updated .env file with domain: $domain (preserved existing API keys) and enforced HTTP_PORT=80/HTTPS_PORT=443${NC}"
}

# Validate email format
validate_email() {
    local email="$1"
    if [[ "$email" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
        return 0
    else
        return 1
    fi
}

# Main execution
main() {
    # Validate email format
    if ! validate_email "$ACME_EMAIL"; then
        echo -e "${RED}❌ Invalid email format: $ACME_EMAIL${NC}"
        exit 1
    fi

    # Detect public IP (only needed for nip.io and sslip.io)
    if [ "$DOMAIN_SERVICE" = "nip.io" ] || [ "$DOMAIN_SERVICE" = "sslip.io" ]; then
        if ! public_ip=$(detect_public_ip); then
            echo -e "${RED}❌ Failed to detect public IP for service: $DOMAIN_SERVICE${NC}"
            exit 1
        fi
    else
        public_ip="N/A"
    fi

    # Generate domain
    if ! domain=$(generate_domain "$public_ip" "$DOMAIN_SERVICE"); then
        exit 1
    fi

    echo -e "${GREEN}✅ Generated domain: $domain${NC}"

    # Update .env file
    update_env_file "$domain" "$ACME_EMAIL"

    echo ""
    echo -e "${GREEN}🚀 HTTPS setup completed successfully!${NC}"
    echo ""
    echo -e "${BLUE}📋 Configuration Summary:${NC}"
    echo "   Service: $DOMAIN_SERVICE"
    echo "   Domain:  $domain"
    echo "   Email:   $ACME_EMAIL"
    if [ "$public_ip" != "N/A" ]; then
        echo "   IP:      $public_ip"
    fi
    echo ""
    echo -e "${BLUE}🚀 Next steps:${NC}"
    echo "1. Run: docker compose up -d"
    echo "2. Wait for SSL certificate generation (1-2 minutes)"
    echo "3. Check logs: docker compose logs -f traefik"
    echo ""
    echo -e "${BLUE}🌐 Your services will be available at:${NC}"
    echo "   - AI Proxy: https://$domain"
    echo "   - Traefik Dashboard: https://traefik.$domain"
    echo ""
    echo -e "${BLUE}🔍 Troubleshooting:${NC}"
    echo "   - Check certificate status: docker compose logs traefik"
    echo "   - Verify domain accessibility: curl -I http://$domain"
    echo "   - Test HTTPS: curl -I https://$domain"

    return 0
}

# Run main function
main
