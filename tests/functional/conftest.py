"""
Configuration for functional tests.

This module provides common fixtures and setup for functional tests
that require real API keys and external service calls.
"""

import os
import pytest


def pytest_configure(config):
    """Configure pytest for functional tests."""
    # Add custom markers
    config.addinivalue_line(
        "markers",
        "functional: marks tests as functional (require real API keys)"
    )
    config.addinivalue_line(
        "markers", 
        "slow: marks tests as slow running"
    )


def pytest_collection_modifyitems(config, items):
    """Modify test collection to add markers."""
    for item in items:
        # Mark all tests in functional directory as functional
        if "functional" in str(item.fspath):
            item.add_marker(pytest.mark.functional)
            item.add_marker(pytest.mark.slow)


@pytest.fixture(scope="session")
def docker_container_check():
    """Ensure tests run in Docker container."""
    if not os.getenv("DOCKER_CONTAINER"):
        pytest.fail(
            "Functional tests must run in Docker container. "
            "Use 'make test-functional' to run these tests."
        )


@pytest.fixture(scope="session")
def api_keys_check():
    """Check that required API keys are available."""
    missing_keys = []
    
    if not os.getenv("API_KEYS"):
        missing_keys.append("API_KEYS")
    
    # Check for at least one provider API key
    has_provider_key = any([
        os.getenv("GEMINI_API_KEY"),
        os.getenv("OPENROUTER_API_KEY")
    ])
    
    if not has_provider_key:
        missing_keys.append("GEMINI_API_KEY or OPENROUTER_API_KEY")
    
    if missing_keys:
        pytest.skip(f"Missing required environment variables: {', '.join(missing_keys)}")


@pytest.fixture(scope="session")
def service_availability_check():
    """Check that the AI proxy service is running and accessible."""
    import httpx
    import asyncio
    
    base_url = os.getenv("FUNCTIONAL_TEST_BASE_URL", "http://localhost:8123")
    
    async def check_service():
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(f"{base_url}/health")
                return response.status_code == 200
        except Exception:
            return False
    
    if not asyncio.run(check_service()):
        pytest.skip(
            f"AI proxy service not available at {base_url}. "
            "Make sure the service is running before running functional tests."
        )


@pytest.fixture(scope="session", autouse=True)
def setup_functional_tests(docker_container_check, api_keys_check, service_availability_check):
    """Set up functional tests environment."""
    # This fixture runs all the checks automatically
    pass 