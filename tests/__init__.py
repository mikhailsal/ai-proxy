"""
Test configuration and utilities.

This module ensures all tests run only in Docker environments.
"""

import os
import sys
from pathlib import Path


def is_running_in_docker() -> bool:
    """
    Check if the current process is running inside a Docker container.
    
    Returns:
        bool: True if running in Docker, False otherwise
    """
    # Check for Docker-specific files and environment variables
    docker_indicators = [
        # Check for .dockerenv file (created by Docker)
        Path("/.dockerenv").exists(),
        # Check for Docker-specific environment variables
        os.getenv("DOCKER_CONTAINER") == "true",
        # Check for common Docker container indicators
        os.getenv("container") == "docker",
        # Check if we're in a container by looking at cgroup
        _check_cgroup_docker(),
    ]
    
    return any(docker_indicators)


def _check_cgroup_docker() -> bool:
    """Check if running in Docker by examining cgroup information."""
    try:
        with open("/proc/1/cgroup", "r") as f:
            content = f.read()
            return "docker" in content or "containerd" in content
    except (FileNotFoundError, PermissionError):
        return False


def enforce_docker_only():
    """
    Enforce that tests only run in Docker environments.
    
    Raises:
        RuntimeError: If not running in Docker
    """
    if not is_running_in_docker():
        error_msg = (
            "\n" + "="*60 + "\n"
            "ERROR: Tests must run only in Docker!\n"
            "="*60 + "\n"
            "This project requires all tests to be executed within Docker containers.\n"
            "\n"
            "To run tests properly, use one of these commands:\n"
            "  make test          # Run all tests in Docker\n"
            "  make test-unit     # Run unit tests in Docker\n"
            "  make test-integration # Run integration tests in Docker\n"
            "\n"
            "Or use Docker directly:\n"
            "  docker-compose run --rm ai-proxy pytest tests/\n"
            "\n"
            "Running tests outside Docker is not allowed to ensure:\n"
            "- Consistent test environment\n"
            "- Proper isolation\n"
            "- Reproducible results\n"
            "="*60 + "\n"
        )
        raise RuntimeError(error_msg)


# Automatically enforce Docker-only testing when tests module is imported
enforce_docker_only()
