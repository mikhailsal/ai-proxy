#!/bin/bash

# AI Proxy Production Deployment Script
# This script safely deploys code changes to production while preserving
# production-specific files like .env, certificates, and logs.

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
REMOTE_HOST="${DEPLOY_HOST:-}"
REMOTE_PATH="${DEPLOY_PATH:-/root/ai-proxy}"
BACKUP_DIR="$REMOTE_PATH/backups"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
LOG_DIR="/tmp/ai-proxy-deploy-logs"
mkdir -p "$LOG_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

success() {
    echo -e "${GREEN}✅ $1${NC}"
}

warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

error() {
    echo -e "${RED}❌ $1${NC}"
    exit 1
}

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    # Check if DEPLOY_HOST is set
    if [[ -z "$REMOTE_HOST" ]]; then
        error "DEPLOY_HOST environment variable is required. Example: DEPLOY_HOST=senki1 $0"
    fi
    
    # Check if we're in the right directory
    if [[ ! -f "$PROJECT_DIR/pyproject.toml" ]] || [[ ! -f "$PROJECT_DIR/docker-compose.yml" ]]; then
        error "Not in AI Proxy project directory"
    fi
    
    # Check if remote host is accessible
    if ! ssh -o ConnectTimeout=5 "$REMOTE_HOST" "echo 'Connection test successful'" >/dev/null 2>&1; then
        error "Cannot connect to remote host: $REMOTE_HOST"
    fi
    
    # Check if remote directory exists, create if needed
    if ! ssh "$REMOTE_HOST" "test -d '$REMOTE_PATH'"; then
        warning "Remote directory does not exist: $REMOTE_PATH"
        log "Creating remote directory..."
        if ssh "$REMOTE_HOST" "mkdir -p '$REMOTE_PATH'"; then
            success "Created remote directory: $REMOTE_PATH"
        else
            error "Failed to create remote directory: $REMOTE_PATH"
        fi
    fi
    
    # Check and install rsync on remote host if needed
    log "Checking rsync availability..."
    if ! ssh "$REMOTE_HOST" "command -v rsync >/dev/null 2>&1"; then
        warning "rsync not found on remote host, attempting to install..."
        
        # Try to install rsync
        if ssh "$REMOTE_HOST" "command -v apt-get >/dev/null 2>&1"; then
            # Debian/Ubuntu
            ssh "$REMOTE_HOST" "apt-get update && apt-get install -y rsync" || {
                error "Failed to install rsync. Please install manually: apt-get install rsync"
            }
        elif ssh "$REMOTE_HOST" "command -v yum >/dev/null 2>&1"; then
            # RHEL/CentOS
            ssh "$REMOTE_HOST" "yum install -y rsync" || {
                error "Failed to install rsync. Please install manually: yum install rsync"
            }
        elif ssh "$REMOTE_HOST" "command -v dnf >/dev/null 2>&1"; then
            # Fedora
            ssh "$REMOTE_HOST" "dnf install -y rsync" || {
                error "Failed to install rsync. Please install manually: dnf install rsync"
            }
        else
            error "Cannot install rsync automatically. Please install rsync on the remote host manually."
        fi
        
        success "rsync installed successfully"
    else
        success "rsync is available"
    fi
    
    success "Prerequisites check passed"
}

# Install Docker if not available
install_docker_if_needed() {
    log "Checking Docker installation..."
    
    if ssh "$REMOTE_HOST" "command -v docker >/dev/null 2>&1"; then
        success "Docker is already installed"
        return 0
    fi
    
    warning "Docker not found, installing Docker..."
    
    ssh "$REMOTE_HOST" "
        # Install Docker using official installation script
        curl -fsSL https://get.docker.com -o get-docker.sh &&
        sh get-docker.sh &&
        rm get-docker.sh &&
        
        # Start and enable Docker service
        systemctl start docker &&
        systemctl enable docker &&
        
        # Add current user to docker group (if not root)
        if [ \"\$(id -u)\" != \"0\" ]; then
            usermod -aG docker \$(whoami)
        fi
    " > "$LOG_DIR/docker-install-$TIMESTAMP.log" 2>&1
    
    if [ $? -eq 0 ]; then
        success "Docker installed successfully"
        return 0
    else
        error "Failed to install Docker. Check logs: $LOG_DIR/docker-install-$TIMESTAMP.log"
    fi
}

# Detect Docker Compose command (supports both v1 and v2)
detect_docker_compose_command() {
    log "Detecting Docker Compose command..."
    
    # Check if docker compose (v2) is available
    if ssh "$REMOTE_HOST" "docker compose version >/dev/null 2>&1"; then
        DOCKER_COMPOSE_CMD="docker compose"
        success "Using Docker Compose v2: docker compose"
    # Check if docker-compose (v1) is available
    elif ssh "$REMOTE_HOST" "docker-compose --version >/dev/null 2>&1"; then
        DOCKER_COMPOSE_CMD="docker-compose"
        success "Using Docker Compose v1: docker-compose"
    else
        error "Neither 'docker compose' nor 'docker-compose' is available on remote host"
    fi
}

# Create backup
create_backup() {
    log "Creating backup on remote server..."
    
    ssh "$REMOTE_HOST" "
        mkdir -p '$BACKUP_DIR' &&
        cd '$REMOTE_PATH' &&
        tar -czf '$BACKUP_DIR/ai-proxy-backup-$TIMESTAMP.tar.gz' \
            --exclude='backups' \
            --exclude='logs/*.log' \
            --exclude='.git' \
            . 2>&1
    " > "$LOG_DIR/backup-$TIMESTAMP.log"
    
    success "Backup created: ai-proxy-backup-$TIMESTAMP.tar.gz"
}

# Get list of files to sync (exclude production-specific files)
get_sync_files() {
    # Files and directories to sync (code only)
    cat << 'EOF'
ai_proxy/
config.yml
pyproject.toml
poetry.lock
Dockerfile
docker-compose.yml
README.md
scripts/
tests/
EOF
}

# Sync files to remote
sync_files() {
    log "Syncing code files to production..."
    
    # CRITICAL: Only sync specific code files, never entire directories
    # This prevents accidentally deleting production configs, certs, logs, etc.
    
    # Sync main application code (quietly)
    scp -r -q "$PROJECT_DIR/ai_proxy/" "$REMOTE_HOST:$REMOTE_PATH/" 2>"$LOG_DIR/sync-ai_proxy-$TIMESTAMP.log"
    
    # Sync individual configuration files (not directories)
    local config_files=(
        "config.yml"
        "pyproject.toml"
        "poetry.lock"
        "Dockerfile"
        "docker-compose.yml"
        "README.md"
        ".env.example"
        "deployment-timestamp.txt"
    )
    
    # Check if this is first deployment (no .env on remote)
    if ! ssh "$REMOTE_HOST" "test -f '$REMOTE_PATH/.env'"; then
        log "First deployment detected - syncing local .env file"
        config_files+=(".env")
    else
        log "Existing .env found on remote - preserving it"
    fi
    
    for file in "${config_files[@]}"; do
        if [[ -f "$PROJECT_DIR/$file" ]]; then
            scp -q "$PROJECT_DIR/$file" "$REMOTE_HOST:$REMOTE_PATH/" 2>>"$LOG_DIR/sync-config-$TIMESTAMP.log"
        fi
    done
    
    # Sync scripts and tests directories (quietly)
    scp -r -q "$PROJECT_DIR/scripts/" "$REMOTE_HOST:$REMOTE_PATH/" 2>>"$LOG_DIR/sync-scripts-$TIMESTAMP.log"
    if [[ -d "$PROJECT_DIR/tests" ]]; then
        scp -r -q "$PROJECT_DIR/tests/" "$REMOTE_HOST:$REMOTE_PATH/" 2>>"$LOG_DIR/sync-tests-$TIMESTAMP.log"
    fi
    
    # NEVER sync these production-specific directories:
    # - .env files (production secrets)
    # - certs/ (SSL certificates)
    # - logs/ (production logs)
    # - traefik/ (traefik config and acme.json)
    # - backups/ (backup files)
    
    success "Files synced successfully (production configs preserved)"
}

# Check service health before deployment
check_service_health() {
    log "Checking current service health..."
    
    local health_status=$(ssh "$REMOTE_HOST" "
        cd '$REMOTE_PATH' &&
        DOMAIN=\$(grep '^DOMAIN=' .env | cut -d= -f2) &&
        HTTPS_PORT=\$(grep '^HTTPS_PORT=' .env | cut -d= -f2) &&
        BASE_URL=\"https://\$DOMAIN\${HTTPS_PORT:+:\$HTTPS_PORT}\" &&
        curl -s \"\$BASE_URL/health\" --max-time 10 || echo 'FAILED'
    ")
    
    if [[ "$health_status" == *'"status":"ok"'* ]]; then
        success "Service is healthy before deployment"
        return 0
    else
        warning "Service health check failed, proceeding anyway..."
        return 1
    fi
}

# Deploy the application
deploy_application() {
    log "Deploying application using docker compose..."
    
    ssh "$REMOTE_HOST" "
        cd '$REMOTE_PATH' &&
        $DOCKER_COMPOSE_CMD down 2>&1 &&
        $DOCKER_COMPOSE_CMD build --no-cache ai-proxy 2>&1 &&
        $DOCKER_COMPOSE_CMD up -d 2>&1 &&
        sleep 10
    " > "$LOG_DIR/deploy-$TIMESTAMP.log" 2>&1
    
    success "Application deployed"
}

# Verify deployment
verify_deployment() {
    log "Verifying deployment..."
    
    # Wait for service to be ready
    local max_attempts=30
    local attempt=1
    
    while [[ $attempt -le $max_attempts ]]; do
        if [[ $attempt -eq 1 ]] || [[ $((attempt % 5)) -eq 0 ]]; then
            log "Health check attempt $attempt/$max_attempts..."
        fi
        
        local health_status=$(ssh "$REMOTE_HOST" "
            cd '$REMOTE_PATH' &&
            DOMAIN=\$(grep '^DOMAIN=' .env | cut -d= -f2) &&
            HTTPS_PORT=\$(grep '^HTTPS_PORT=' .env | cut -d= -f2) &&
            BASE_URL=\"https://\$DOMAIN\${HTTPS_PORT:+:\$HTTPS_PORT}\" &&
            curl -s \"\$BASE_URL/health\" --max-time 10 || echo 'FAILED'
        " 2>>"$LOG_DIR/health-check-$TIMESTAMP.log")
        
        if [[ "$health_status" == *'"status":"ok"'* ]]; then
            success "Service is healthy after deployment"
            break
        fi
        
        if [[ $attempt -eq $max_attempts ]]; then
            error "Service health check failed after deployment"
        fi
        
        sleep 1
        ((attempt++))
    done
    
    # Test basic functionality
    log "Testing basic functionality..."
    
    local test_result=$(ssh "$REMOTE_HOST" "
        cd '$REMOTE_PATH' &&
        DOMAIN=\$(grep '^DOMAIN=' .env | cut -d= -f2) &&
        HTTPS_PORT=\$(grep '^HTTPS_PORT=' .env | cut -d= -f2) &&
        API_KEY=\$(grep '^API_KEYS=' .env | cut -d= -f2 | cut -d, -f1) &&
        BASE_URL=\"https://\$DOMAIN\${HTTPS_PORT:+:\$HTTPS_PORT}\" &&
        curl -s \"\$BASE_URL/v1/chat/completions\" \
            -H \"Content-Type: application/json\" \
            -H \"Authorization: Bearer \$API_KEY\" \
            -d '{\"model\": \"gemini-pro\", \"messages\": [{\"role\": \"user\", \"content\": \"Hello\"}]}' \
            --max-time 30 | head -1
    ")
    
    if [[ "$test_result" == *'"id"'* ]]; then
        success "Basic functionality test passed"
    else
        warning "Basic functionality test failed, but service is healthy"
    fi
    
    success "Deployment verification completed"
}

# List available backups
list_backups() {
    log "Available backups on $REMOTE_HOST:"
    
    ssh "$REMOTE_HOST" "
        cd '$BACKUP_DIR' &&
        if ls ai-proxy-backup-*.tar.gz >/dev/null 2>&1; then
            echo '' &&
            echo 'Available backups:' &&
            echo '==================' &&
            ls -la ai-proxy-backup-*.tar.gz | awk '{
                # Extract timestamp from filename (format: ai-proxy-backup-YYYYMMDD-HHMMSS.tar.gz)
                filename = \$9;
                gsub(/.*backup-/, \"\", filename);
                gsub(/\\.tar\\.gz.*/, \"\", filename);
                split(filename, parts, \"-\");
                if (length(parts) >= 2 && length(parts[1]) == 8 && length(parts[2]) == 6) {
                    date_part = parts[1];
                    time_part = parts[2];
                    formatted_date = substr(date_part, 1, 4) \"-\" substr(date_part, 5, 2) \"-\" substr(date_part, 7, 2);
                    formatted_time = substr(time_part, 1, 2) \":\" substr(time_part, 3, 2) \":\" substr(time_part, 5, 2);
                    timestamp = formatted_date \" \" formatted_time;
                } else {
                    timestamp = \"Unknown format\";
                }
                printf \"%-45s %8s %s\\n\", \$9, \$5, timestamp
            }' &&
            echo '' &&
            echo 'Usage: DEPLOY_HOST=$REMOTE_HOST $0 --restore-backup <backup-filename>'
        else
            echo 'No backups found in $BACKUP_DIR'
        fi
    "
}

# Restore specific backup
restore_backup() {
    local backup_file="$1"
    
    if [[ -z "$backup_file" ]]; then
        error "Backup filename is required. Use --list-backups to see available backups."
    fi
    
    # Check if backup exists
    if ! ssh "$REMOTE_HOST" "test -f '$BACKUP_DIR/$backup_file'"; then
        error "Backup file not found: $backup_file"
    fi
    
    warning "Restoring from specific backup: $backup_file"
    
    # Create a backup of current state before restoration
    log "Creating safety backup of current state..."
    ssh "$REMOTE_HOST" "
        cd '$REMOTE_PATH' &&
        tar -czf '$BACKUP_DIR/safety-backup-before-restore-$TIMESTAMP.tar.gz' \
            --exclude='backups' \
            --exclude='logs/*.log' \
            --exclude='.git' \
            .
    "
    
    log "Restoring from backup: $backup_file"
    
    ssh "$REMOTE_HOST" "
        cd '$REMOTE_PATH' &&
        $DOCKER_COMPOSE_CMD down 2>&1 &&
        tar -xzf '$BACKUP_DIR/$backup_file' 2>&1 &&
        $DOCKER_COMPOSE_CMD build --no-cache ai-proxy 2>&1 &&
        $DOCKER_COMPOSE_CMD up -d 2>&1 &&
        sleep 10
    " > "$LOG_DIR/restore-$backup_file-$TIMESTAMP.log" 2>&1
    
    success "Backup restoration completed"
    log "Safety backup created: safety-backup-before-restore-$TIMESTAMP.tar.gz"
}

# Rollback function (uses latest backup)
rollback() {
    warning "Rolling back to previous version..."
    
    local latest_backup=$(ssh "$REMOTE_HOST" "ls -t '$BACKUP_DIR'/ai-proxy-backup-*.tar.gz | head -1")
    
    if [[ -z "$latest_backup" ]]; then
        error "No backup found for rollback"
    fi
    
    log "Using backup: $(basename "$latest_backup")"
    
    ssh "$REMOTE_HOST" "
        cd '$REMOTE_PATH' &&
        $DOCKER_COMPOSE_CMD down 2>&1 &&
        tar -xzf '$latest_backup' 2>&1 &&
        $DOCKER_COMPOSE_CMD build --no-cache ai-proxy 2>&1 &&
        $DOCKER_COMPOSE_CMD up -d 2>&1 &&
        sleep 10
    " > "$LOG_DIR/rollback-$TIMESTAMP.log" 2>&1
    
    success "Rollback completed"
}

# Cleanup old backups
cleanup_backups() {
    log "Cleaning up old backups (keeping last 5)..."
    
    ssh "$REMOTE_HOST" "
        cd '$BACKUP_DIR' &&
        ls -t ai-proxy-backup-*.tar.gz | tail -n +6 | xargs -r rm -f &&
        echo 'Remaining backups:' &&
        ls -la ai-proxy-backup-*.tar.gz 2>/dev/null || echo 'No backups found'
    "
    
    success "Backup cleanup completed"
}

# Check if HTTPS is already configured
check_https_configuration() {
    log "Checking HTTPS configuration..."
    
    local https_configured=false
    
    # Check if traefik container exists and is running
    local traefik_status=$(ssh "$REMOTE_HOST" "
        cd '$REMOTE_PATH' &&
        docker ps --format 'table {{.Names}}\t{{.Status}}' | grep traefik || echo 'NOT_FOUND'
    ")
    
    # Check if SSL certificates exist
    local certs_exist=$(ssh "$REMOTE_HOST" "
        test -f '$REMOTE_PATH/certs/acme.json' && echo 'EXISTS' || echo 'NOT_EXISTS'
    ")
    
    # Check if .env has DOMAIN configured
    local domain_configured=$(ssh "$REMOTE_HOST" "
        cd '$REMOTE_PATH' &&
        if [ -f .env ]; then
            DOMAIN=\$(grep '^DOMAIN=' .env | cut -d= -f2)
            if [ -n \"\$DOMAIN\" ] && [ \"\$DOMAIN\" != \"your-domain.com\" ]; then
                echo 'CONFIGURED'
            else
                echo 'NOT_CONFIGURED'
            fi
        else
            echo 'NO_ENV'
        fi
    ")
    
    if [[ "$traefik_status" == *"Up"* ]] && [[ "$certs_exist" == "EXISTS" ]] && [[ "$domain_configured" == "CONFIGURED" ]]; then
        https_configured=true
    fi
    
    if $https_configured; then
        success "HTTPS is already configured and running"
        return 0
    else
        warning "HTTPS is not properly configured"
        log "Traefik status: $traefik_status"
        log "Certificates exist: $certs_exist"
        log "Domain configured: $domain_configured"
        return 1
    fi
}

# Setup HTTPS configuration on remote server
setup_https_remote() {
    log "Setting up HTTPS configuration on remote server..."
    
    # Copy setup-https.sh script to remote server
    scp -q "$PROJECT_DIR/scripts/setup-https.sh" "$REMOTE_HOST:$REMOTE_PATH/scripts/" 2>"$LOG_DIR/setup-https-copy-$TIMESTAMP.log"
    
    # Make it executable and run it with default settings (nip.io)
    ssh "$REMOTE_HOST" "
        cd '$REMOTE_PATH' &&
        chmod +x scripts/setup-https.sh &&
        ./scripts/setup-https.sh -e info@techsupport-services.com
    " > "$LOG_DIR/setup-https-$TIMESTAMP.log" 2>&1
    
    # Check if HTTPS setup was successful
    local setup_status=$?
    if [[ $setup_status -eq 0 ]]; then
        success "HTTPS setup completed successfully"
        
        # Show the generated domain
        local generated_domain=$(ssh "$REMOTE_HOST" "
            cd '$REMOTE_PATH' &&
            if [ -f .env ]; then
                grep '^DOMAIN=' .env | cut -d= -f2
            fi
        ")
        
        if [[ -n "$generated_domain" ]]; then
            log "Generated domain: $generated_domain"
        fi
        
        return 0
    else
        warning "HTTPS setup failed"
        log "Check setup logs: $LOG_DIR/setup-https-$TIMESTAMP.log"
        return 1
    fi
}

# Main deployment function
main() {
    local action="${1:-}"
    local backup_file="${2:-}"
    
    log "Starting AI Proxy production deployment..."
    log "Remote host: $REMOTE_HOST"
    log "Remote path: $REMOTE_PATH"
    log "Timestamp: $TIMESTAMP"
    
    # Create deployment timestamp file locally, to be included in the build
    echo "$TIMESTAMP" > "$PROJECT_DIR/deployment-timestamp.txt"

    # Trap to handle rollback on failure (only for normal deployments)
    if [[ "$action" == "" ]]; then
        trap 'error "Deployment failed! Run with --rollback to restore previous version"' ERR
    fi
    
    check_prerequisites
    
    # Handle different actions
    case "$action" in
        "--rollback")
            install_docker_if_needed
            detect_docker_compose_command
            rollback
            verify_deployment
            return 0
            ;;
        "--list-backups")
            list_backups
            return 0
            ;;
        "--restore-backup")
            install_docker_if_needed
            detect_docker_compose_command
            restore_backup "$backup_file"
            verify_deployment
            return 0
            ;;
        "")
            # Normal deployment
            install_docker_if_needed
            detect_docker_compose_command
            ;;
        *)
            error "Unknown action: $action"
            ;;
    esac
    
    # Store current health status
    local was_healthy=false
    if check_service_health; then
        was_healthy=true
    fi
    
    create_backup
    sync_files
    
    # Check and setup HTTPS if needed (only for normal deployments, after files are synced)
    if [[ "$action" == "" ]]; then
        if ! check_https_configuration; then
            log "HTTPS not configured, setting up HTTPS..."
            if ! setup_https_remote; then
                error "HTTPS setup failed. Please configure domain in .env and try again."
            fi
        fi
    fi
    
    deploy_application
    verify_deployment
    cleanup_backups
    
    # Clean up local timestamp file
    rm -f "$PROJECT_DIR/deployment-timestamp.txt"

    success "🎉 Deployment completed successfully!"
    log "Backup available at: $BACKUP_DIR/ai-proxy-backup-$TIMESTAMP.tar.gz"
    log "Deployment logs available at: $LOG_DIR/"
    
    # Show deployment summary
    ssh "$REMOTE_HOST" "
        cd '$REMOTE_PATH' &&
        echo '' &&
        echo '=== Deployment Summary ===' &&
        echo 'Containers:' &&
        docker ps | grep ai-proxy &&
        echo '' &&
        echo 'Service endpoint:' &&
        DOMAIN=\$(grep '^DOMAIN=' .env | cut -d= -f2) &&
        HTTPS_PORT=\$(grep '^HTTPS_PORT=' .env | cut -d= -f2) &&
        echo \"https://\$DOMAIN\${HTTPS_PORT:+:\$HTTPS_PORT}\"
    "
}

# Script usage
usage() {
    cat << EOF
Usage: $0 [OPTIONS] [BACKUP_FILE]

Deploy AI Proxy to production server with backup management.

OPTIONS:
    --rollback                     Rollback to the most recent backup
    --list-backups                 List all available backups
    --restore-backup <filename>    Restore from a specific backup file
    --help                         Show this help message

ENVIRONMENT VARIABLES:
    DEPLOY_HOST   Remote host (required)
    DEPLOY_PATH   Remote path (default: /root/ai-proxy)

EXAMPLES:
    # Normal deployment
    DEPLOY_HOST=senki1 $0

    # Backup management
    DEPLOY_HOST=senki1 $0 --list-backups
    DEPLOY_HOST=senki1 $0 --rollback
    DEPLOY_HOST=senki1 $0 --restore-backup ai-proxy-backup-20250702-171225.tar.gz

    # Custom host
    DEPLOY_HOST=myserver $0

EOF
}

# Handle command line arguments
case "${1:-}" in
    --help)
        usage
        exit 0
        ;;
    --rollback)
        main --rollback
        ;;
    --list-backups)
        main --list-backups
        ;;
    --restore-backup)
        if [[ -z "${2:-}" ]]; then
            error "Backup filename is required for --restore-backup option"
        fi
        main --restore-backup "$2"
        ;;
    "")
        main
        ;;
    *)
        error "Unknown option: $1. Use --help for usage information."
        ;;
esac 