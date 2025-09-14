#!/bin/bash

# Ensure deployment timestamp script
# Creates /app/deployment-timestamp.txt if missing for health endpoint

TIMESTAMP_FILE="/app/deployment-timestamp.txt"

if [ ! -f "$TIMESTAMP_FILE" ]; then
    echo "dev-build-$(date +%Y%m%d-%H%M%S)" > "$TIMESTAMP_FILE"
    echo "Created dev build timestamp: $(cat $TIMESTAMP_FILE)"
else
    echo "Using existing deployment timestamp: $(cat $TIMESTAMP_FILE)"
fi

# Execute the original command
exec "$@" 

