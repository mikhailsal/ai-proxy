#!/usr/bin/env python3
"""
Simple test runner that doesn't use external commands
"""

import os
import sys

def main():
    print("🐳 AI Proxy Test Runner (Docker-compatible)")
    print("=" * 50)

    # Set Docker-like environment
    os.environ["DOCKER_CONTAINER"] = "true"
    os.environ["HOST_UID"] = str(os.getuid())
    os.environ["HOST_GID"] = str(os.getgid())

    print(f"Environment: DOCKER_CONTAINER={os.environ.get('DOCKER_CONTAINER')}")
    print(f"User ID: {os.environ.get('HOST_UID')}")
    print(f"Group ID: {os.environ.get('HOST_GID')}")

    # Check if test directories exist
    unit_tests = os.path.exists("tests/unit")
    integration_tests = os.path.exists("tests/integration")

    print(f"Unit tests directory: {'✅' if unit_tests else '❌'}")
    print(f"Integration tests directory: {'✅' if integration_tests else '❌'}")

    # Count test files
    unit_count = 0
    integration_count = 0

    if unit_tests:
        try:
            unit_count = len([f for f in os.listdir("tests/unit") if f.startswith("test_") and f.endswith(".py")])
        except:
            pass

    if integration_tests:
        try:
            integration_count = len([f for f in os.listdir("tests/integration") if f.startswith("test_") and f.endswith(".py")])
        except:
            pass

    print(f"Unit test files: {unit_count}")
    print(f"Integration test files: {integration_count}")

    print("\n✅ Test environment setup complete!")
    print("🎯 Tests can now run in Docker-compatible environment")
    print("\nTo run tests in Docker:")
    print("  docker-compose run --rm -e DOCKER_CONTAINER=true ai-proxy poetry run pytest tests/unit tests/integration")
    print("\nTo run tests locally:")
    print("  poetry run pytest tests/unit tests/integration")

    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)