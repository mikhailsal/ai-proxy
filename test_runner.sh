#!/bin/bash
# Simple test runner script

echo "🐳 AI Proxy Docker Test Runner"
echo "=============================="

# Set environment like Docker
export DOCKER_CONTAINER=true
export HOST_UID=$(id -u)
export HOST_GID=$(id -g)

echo "Environment variables:"
echo "  DOCKER_CONTAINER=$DOCKER_CONTAINER"
echo "  HOST_UID=$HOST_UID"
echo "  HOST_GID=$HOST_GID"

echo ""
echo "Test directories:"
if [ -d "tests/unit" ]; then
    echo "  ✅ tests/unit exists"
    UNIT_COUNT=$(find tests/unit -name "test_*.py" | wc -l)
    echo "  📁 Unit test files: $UNIT_COUNT"
else
    echo "  ❌ tests/unit not found"
fi

if [ -d "tests/integration" ]; then
    echo "  ✅ tests/integration exists"
    INT_COUNT=$(find tests/integration -name "test_*.py" | wc -l)
    echo "  📁 Integration test files: $INT_COUNT"
else
    echo "  ❌ tests/integration not found"
fi

echo ""
echo "✅ Environment ready for Docker testing!"
echo ""
echo "To run tests in Docker container:"
echo "  docker-compose run --rm -e DOCKER_CONTAINER=true ai-proxy poetry run pytest tests/unit tests/integration"
echo ""
echo "To simulate Docker environment locally:"
echo "  DOCKER_CONTAINER=true HOST_UID=\$(id -u) HOST_GID=\$(id -g) poetry run pytest tests/unit tests/integration"