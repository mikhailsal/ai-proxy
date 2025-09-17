#!/bin/bash

# Container Entrypoint Script
# Fixes permissions for mounted volumes and runs the application
# Works inside container without requiring sudo

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${BLUE}[ENTRYPOINT]${NC} $1"
}

success() {
    echo -e "${GREEN}✅ [ENTRYPOINT]${NC} $1"
}

warning() {
    echo -e "${YELLOW}⚠️  [ENTRYPOINT]${NC} $1"
}

# Get current user info inside container
CONTAINER_UID=$(id -u)
CONTAINER_GID=$(id -g)
CONTAINER_USER=$(whoami 2>/dev/null || echo "uid-$CONTAINER_UID")

log "Container running as $CONTAINER_USER (UID:GID = $CONTAINER_UID:$CONTAINER_GID)"

# Fix permissions for mounted directories
fix_mounted_permissions() {
    local directories=(
        "/app/logs"
        "/app/certs"
        "/app/traefik"
        "/app/bundles"
        "/app/tmp"
    )

    for dir in "${directories[@]}"; do
        # Create directory if it doesn't exist
        if [[ ! -d "$dir" ]]; then
            log "Creating directory $dir..."
            mkdir -p "$dir" 2>/dev/null || {
                warning "Could not create $dir"
                continue
            }
        fi

        log "Checking write access to $dir..."

        # Test write permissions by creating a test file
        if touch "$dir/.write-test" 2>/dev/null; then
            rm -f "$dir/.write-test" 2>/dev/null || true
            success "Write access OK for $dir"
        else
            log "No write access to $dir, attempting to fix..."

            # If we're root, we can fix ownership
            if [[ "$CONTAINER_UID" == "0" ]]; then
                chown -R "$CONTAINER_UID:$CONTAINER_GID" "$dir" 2>/dev/null || true
                chmod -R u+rwX,g+rX "$dir" 2>/dev/null || true
                log "Fixed ownership as root for $dir (files will belong to root)"
            else
                # If we're not root, try to fix permissions only
                chmod -R u+rwX "$dir" 2>/dev/null || {
                    warning "Could not fix permissions for $dir (not root and no write access)"
                    continue
                }
                log "Fixed permissions as user for $dir"
            fi

            # Test again
            if touch "$dir/.write-test" 2>/dev/null; then
                rm -f "$dir/.write-test" 2>/dev/null || true
                success "Successfully fixed write access for $dir"
            else
                warning "Still no write access to $dir - application may have issues"
            fi
        fi
    done
}

# Ensure proper ownership of application files
fix_app_permissions() {
    # Only fix if we're root - non-root users can't change ownership
    if [[ "$CONTAINER_UID" == "0" ]]; then
        log "Running as root - ensuring proper ownership of app files..."

        # Fix ownership of key application files
        chown -R root:root /app/ai_proxy /app/ai_proxy_ui 2>/dev/null || true
        chmod -R u+rwX,g+rX,o+rX /app/ai_proxy /app/ai_proxy_ui 2>/dev/null || true

        success "Fixed ownership of application files"
    else
        log "Running as non-root user - skipping app file ownership changes"
    fi
}

# Main execution
main() {
    log "Starting container entrypoint..."

    # Fix permissions for mounted directories
    fix_mounted_permissions

    # Fix application file permissions if running as root
    fix_app_permissions

    success "Entrypoint setup complete, starting application..."

    # Execute the original command
    exec "$@"
}

# Run main function with all arguments
main "$@"
