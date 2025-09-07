"""
General functional tests that don't depend on specific providers.

These tests verify general API functionality, authentication, and error handling
that works across all providers.

⚠️  WARNING: These tests make real HTTP requests but don't consume external API quotas!
    They are disabled by default and should only be run when explicitly enabled.
"""

import os
import pytest
import pytest_asyncio
import httpx

pytestmark = [pytest.mark.asyncio]


class TestGeneralAuthentication:
    """Test authentication and authorization functionality."""

    @pytest.fixture
    def api_key(self):
        """Get API key from environment."""
        api_keys = os.getenv("API_KEYS", "")
        if not api_keys:
            pytest.skip("API_KEYS environment variable not set")
        return api_keys.split(",")[0].strip()

    @pytest.fixture
    def base_url(self):
        """Get base URL for the proxy service."""
        return os.getenv("FUNCTIONAL_TEST_BASE_URL", "http://localhost:8123")

    @pytest_asyncio.fixture
    async def client(self, base_url):
        """Create HTTP client for making requests."""
        async with httpx.AsyncClient(base_url=base_url, timeout=30.0) as client:
            yield client

    async def test_invalid_api_key(self, client):
        """Test that invalid API key returns 401."""
        payload = {
            "model": "gemini-pro",
            "messages": [
                {
                    "role": "user",
                    "content": "Hello"
                }
            ]
        }

        response = await client.post(
            "/v1/chat/completions",
            json=payload,
            headers={"Authorization": "Bearer invalid-key"}
        )

        assert response.status_code == 401

    async def test_missing_api_key(self, client):
        """Test that missing API key returns 401."""
        payload = {
            "model": "gemini-pro",
            "messages": [
                {
                    "role": "user",
                    "content": "Hello"
                }
            ]
        }

        response = await client.post(
            "/v1/chat/completions",
            json=payload
        )

        assert response.status_code == 401

    async def test_options_request(self, client):
        """Test CORS preflight request."""
        response = await client.options("/v1/chat/completions")

        assert response.status_code == 200
        assert "Access-Control-Allow-Origin" in response.headers
        assert "Access-Control-Allow-Methods" in response.headers
        assert "Access-Control-Allow-Headers" in response.headers


class TestGeneralEdgeCases:
    """Test general edge cases that work across all providers."""

    @pytest.fixture
    def api_key(self):
        """Get API key from environment."""
        api_keys = os.getenv("API_KEYS", "")
        if not api_keys:
            pytest.skip("API_KEYS environment variable not set")
        return api_keys.split(",")[0].strip()

    @pytest.fixture
    def base_url(self):
        """Get base URL for the proxy service."""
        return os.getenv("FUNCTIONAL_TEST_BASE_URL", "http://localhost:8123")

    @pytest_asyncio.fixture
    async def client(self, base_url):
        """Create HTTP client for making requests."""
        async with httpx.AsyncClient(base_url=base_url, timeout=30.0) as client:
            yield client

    async def test_invalid_model(self, client, api_key):
        """Test that invalid model returns appropriate error."""
        payload = {
            "model": "nonexistent-model",
            "messages": [
                {
                    "role": "user",
                    "content": "Hello"
                }
            ]
        }

        response = await client.post(
            "/v1/chat/completions",
            json=payload,
            headers={"Authorization": f"Bearer {api_key}"}
        )

        # Should return an error (400 or 500 depending on implementation)
        assert response.status_code >= 400

    async def test_malformed_request(self, client, api_key):
        """Test that malformed request returns 400."""
        payload = {
            "model": "gemini-pro",
            # Missing required 'messages' field
        }

        response = await client.post(
            "/v1/chat/completions",
            json=payload,
            headers={"Authorization": f"Bearer {api_key}"}
        )

        assert response.status_code == 400

    async def test_health_endpoint(self, client):
        """Test that health endpoint is accessible."""
        response = await client.get("/health")
        assert response.status_code == 200

        data = response.json()
        assert data["status"] == "ok"
        assert "version" in data


class TestGeneralEndpoints:
    """Test general API endpoints that don't depend on external providers."""

    @pytest.fixture
    def base_url(self):
        """Get base URL for the proxy service."""
        return os.getenv("FUNCTIONAL_TEST_BASE_URL", "http://localhost:8123")

    @pytest_asyncio.fixture
    async def client(self, base_url):
        """Create HTTP client for making requests."""
        async with httpx.AsyncClient(base_url=base_url, timeout=30.0) as client:
            yield client

    async def test_health_endpoint_unauthenticated(self, client):
        """Test health endpoint works without authentication."""
        response = await client.get("/health")
        assert response.status_code == 200

    async def test_unknown_endpoint(self, client):
        """Test that unknown endpoints return 404."""
        response = await client.get("/unknown-endpoint")
        assert response.status_code == 404

    async def test_root_endpoint(self, client):
        """Test root endpoint response."""
        response = await client.get("/")
        # Could be 404 or redirect, but should not be 500
        assert response.status_code != 500
