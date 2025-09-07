#!/bin/bash

# Script to wait for AI proxy service to be available
# Usage: ./wait-for-service.sh [url] [timeout]

URL=${1:-"http://ai-proxy:8123/health"}
TIMEOUT=${2:-120}

echo "Waiting for AI proxy service..."
count=0

while ! curl -s --max-time 5 "$URL" > /dev/null 2>&1; do
    count=$((count + 1))
    if [ $count -ge $TIMEOUT ]; then
        echo "ERROR: Timeout waiting for AI proxy service after $TIMEOUT seconds"
        exit 1
    fi
    # Only show progress every 10 seconds to reduce output
    if [ $((count % 10)) -eq 0 ]; then
        echo "Still waiting... ($count/$TIMEOUT)"
    fi
    sleep 1
done

echo "AI proxy service is ready!"
exit 0
