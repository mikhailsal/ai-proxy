#!/bin/bash

# Cloudflare Tunnel Management Script for AI Proxy
# Provides a free HTTPS tunnel with trusted certificates (*.trycloudflare.com)
# No signup or account required.

set -euo pipefail

# Configuration
TUNNEL_PORT="${TUNNEL_PORT:-8123}"  # AI Proxy internal port
TUNNEL_LOG="/root/ai-proxy/logs/tunnel.log"
TUNNEL_URL_FILE="/root/ai-proxy/logs/tunnel-url.txt"
TUNNEL_PID_FILE="/root/ai-proxy/logs/tunnel.pid"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log()     { echo -e "${BLUE}[$(date +'%H:%M:%S')]${NC} $1"; }
success() { echo -e "${GREEN}✅ $1${NC}"; }
warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }
error()   { echo -e "${RED}❌ $1${NC}"; exit 1; }

# Check prerequisites
check_prereqs() {
    if ! command -v cloudflared >/dev/null 2>&1; then
        error "cloudflared is not installed. Install: curl -fsSL https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb -o /tmp/cloudflared.deb && dpkg -i /tmp/cloudflared.deb"
    fi

    # Check if ai-proxy is running and healthy
    if ! curl -s --max-time 3 http://127.0.0.1:${TUNNEL_PORT}/health >/dev/null 2>&1; then
        error "AI Proxy is not running on port ${TUNNEL_PORT}. Start it first: cd /root/ai-proxy && docker compose up -d"
    fi

    mkdir -p "$(dirname "$TUNNEL_LOG")"
}

# Start the tunnel
start_tunnel() {
    check_prereqs

    # Check if already running
    if [ -f "$TUNNEL_PID_FILE" ] && kill -0 "$(cat "$TUNNEL_PID_FILE")" 2>/dev/null; then
        local existing_url=""
        [ -f "$TUNNEL_URL_FILE" ] && existing_url=$(cat "$TUNNEL_URL_FILE")
        warning "Tunnel is already running (PID: $(cat "$TUNNEL_PID_FILE"))"
        [ -n "$existing_url" ] && log "URL: $existing_url"
        return 0
    fi

    log "Starting Cloudflare tunnel to http://127.0.0.1:${TUNNEL_PORT}..."

    # Start cloudflared in background, capture output to find the URL
    cloudflared tunnel --url http://127.0.0.1:${TUNNEL_PORT} \
        --no-autoupdate \
        > "$TUNNEL_LOG" 2>&1 &

    local pid=$!
    echo "$pid" > "$TUNNEL_PID_FILE"

    log "Tunnel process started (PID: $pid), waiting for URL..."

    # Wait for the tunnel URL to appear in logs (up to 30 seconds)
    local attempts=0
    local tunnel_url=""
    while [ $attempts -lt 30 ]; do
        tunnel_url=$(grep -oP 'https://[a-zA-Z0-9-]+\.trycloudflare\.com' "$TUNNEL_LOG" 2>/dev/null | head -1 || true)
        if [ -n "$tunnel_url" ]; then
            break
        fi
        sleep 1
        attempts=$((attempts + 1))

        # Check if process is still alive
        if ! kill -0 "$pid" 2>/dev/null; then
            error "Tunnel process died. Check logs: $TUNNEL_LOG"
        fi
    done

    if [ -z "$tunnel_url" ]; then
        kill "$pid" 2>/dev/null || true
        rm -f "$TUNNEL_PID_FILE"
        error "Could not detect tunnel URL after 30 seconds. Check logs: $TUNNEL_LOG"
    fi

    echo "$tunnel_url" > "$TUNNEL_URL_FILE"

    echo ""
    success "Cloudflare tunnel is running!"
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  🌐 Tunnel URL: ${tunnel_url}${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BLUE}📋 Service Endpoints:${NC}"
    echo "   - Health:     ${tunnel_url}/health"
    echo "   - Chat API:   ${tunnel_url}/v1/chat/completions"
    echo "   - Models:     ${tunnel_url}/v1/models"
    echo ""
    echo -e "${BLUE}📝 Notes:${NC}"
    echo "   - Uses Cloudflare's trusted HTTPS certificate (no -k flag needed)"
    echo "   - No signup or account required"
    echo "   - URL changes on each restart (use 'tunnel.sh status' to check)"
    echo "   - PID: $pid | Logs: $TUNNEL_LOG"
    echo ""
}

# Stop the tunnel
stop_tunnel() {
    if [ -f "$TUNNEL_PID_FILE" ]; then
        local pid=$(cat "$TUNNEL_PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            log "Stopping tunnel (PID: $pid)..."
            kill "$pid" 2>/dev/null
            # Wait for graceful shutdown
            local wait=0
            while kill -0 "$pid" 2>/dev/null && [ $wait -lt 10 ]; do
                sleep 1
                wait=$((wait + 1))
            done
            # Force kill if still alive
            kill -9 "$pid" 2>/dev/null || true
            success "Tunnel stopped"
        else
            warning "Tunnel process (PID: $pid) is not running"
        fi
        rm -f "$TUNNEL_PID_FILE"
    else
        warning "No tunnel PID file found"
    fi
}

# Show tunnel status
status_tunnel() {
    if [ -f "$TUNNEL_PID_FILE" ] && kill -0 "$(cat "$TUNNEL_PID_FILE")" 2>/dev/null; then
        local pid=$(cat "$TUNNEL_PID_FILE")
        local url=""
        [ -f "$TUNNEL_URL_FILE" ] && url=$(cat "$TUNNEL_URL_FILE")
        success "Tunnel is running (PID: $pid)"
        [ -n "$url" ] && echo -e "   🌐 URL: ${GREEN}${url}${NC}"

        # Quick health check through tunnel
        if [ -n "$url" ]; then
            local health=$(curl -s --max-time 5 "${url}/health" 2>/dev/null || echo "FAILED")
            if echo "$health" | grep -q '"status"'; then
                success "Health check through tunnel: OK"
            else
                warning "Health check through tunnel failed"
            fi
        fi
    else
        warning "Tunnel is not running"
        [ -f "$TUNNEL_URL_FILE" ] && echo "   Last known URL: $(cat "$TUNNEL_URL_FILE")"
    fi
}

# Restart the tunnel
restart_tunnel() {
    stop_tunnel
    sleep 2
    start_tunnel
}

# Show usage
usage() {
    cat << EOF
Usage: $0 {start|stop|status|restart|url|logs}

Commands:
    start     Start the Cloudflare tunnel
    stop      Stop the tunnel
    status    Show tunnel status and health
    restart   Restart the tunnel (generates new URL)
    url       Print the current tunnel URL
    logs      Show tunnel logs (last 50 lines)

Environment:
    TUNNEL_PORT   Local port to tunnel (default: 8123)

EOF
}

# Main
case "${1:-start}" in
    start)   start_tunnel ;;
    stop)    stop_tunnel ;;
    status)  status_tunnel ;;
    restart) restart_tunnel ;;
    url)
        if [ -f "$TUNNEL_URL_FILE" ]; then
            cat "$TUNNEL_URL_FILE"
        else
            error "No tunnel URL found. Start the tunnel first: $0 start"
        fi
        ;;
    logs)
        if [ -f "$TUNNEL_LOG" ]; then
            tail -50 "$TUNNEL_LOG"
        else
            warning "No tunnel logs found"
        fi
        ;;
    -h|--help|help) usage ;;
    *) error "Unknown command: $1. Use '$0 --help' for usage." ;;
esac
