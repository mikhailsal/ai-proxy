"""
Test configuration and utilities.

This module ensures all tests run only in Docker environments.
"""

import os
from pathlib import Path

# Add project root to the Python path
# This is necessary for tests to find the ai_proxy module


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
