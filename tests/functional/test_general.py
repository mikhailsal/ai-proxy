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
            "messages": [{"role": "user", "content": "Hello"}],
        }

        response = await client.post(
            "/v1/chat/completions",
            json=payload,
            headers={"Authorization": "Bearer invalid-key"},
        )

        assert response.status_code == 401

    async def test_missing_api_key(self, client):
        """Test that missing API key returns 401."""
        payload = {
            "model": "gemini-pro",
            "messages": [{"role": "user", "content": "Hello"}],
        }

        response = await client.post("/v1/chat/completions", json=payload)

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
            "messages": [{"role": "user", "content": "Hello"}],
        }

        response = await client.post(
            "/v1/chat/completions",
            json=payload,
            headers={"Authorization": f"Bearer {api_key}"},
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
            headers={"Authorization": f"Bearer {api_key}"},
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


class TestModelsEndpoint:
    """Test models endpoint functionality."""

    @pytest.fixture
    def base_url(self):
        """Get base URL for the proxy service."""
        return os.getenv("FUNCTIONAL_TEST_BASE_URL", "http://localhost:8123")

    @pytest_asyncio.fixture
    async def client(self, base_url):
        """Create HTTP client for making requests."""
        async with httpx.AsyncClient(base_url=base_url, timeout=30.0) as client:
            yield client

    async def test_models_endpoint_no_auth(self, client):
        """Test that models endpoint works without authentication."""
        response = await client.get("/v1/models")
        assert response.status_code == 200

        data = response.json()
        assert "object" in data
        assert data["object"] == "list"
        assert "data" in data
        assert isinstance(data["data"], list)

        # Should have models configured
        models = data["data"]
        assert len(models) > 0

        # Check model structure
        for model in models:
            assert "id" in model
            assert "object" in model
            assert model["object"] == "model"
            assert "created" in model
            assert "owned_by" in model
            assert "permission" in model
            assert "root" in model
            assert "parent" in model

            # Check that model ID doesn't contain wildcards
            assert "*" not in model["id"]

    async def test_models_endpoint_content_type(self, client):
        """Test that models endpoint returns correct content type."""
        response = await client.get("/v1/models")
        assert response.status_code == 200
        assert "application/json" in response.headers.get("content-type", "")

    async def test_models_endpoint_specific_models_present(self, client):
        """Test that specific models are present in the response."""
        response = await client.get("/v1/models")
        assert response.status_code == 200

        data = response.json()
        models = data["data"]
        model_ids = [model["id"] for model in models]

        # Check that some expected models are present
        expected_models = [
            "gemini-pro",
            "gpt-4",
            "claude-3-opus",
            "mistral-small",
            "deepseek-r1",
            "llama-3.1-8b",
        ]

        for expected_model in expected_models:
            assert (
                expected_model in model_ids
            ), f"Expected model {expected_model} not found in models list"

    async def test_models_endpoint_provider_mapping(self, client):
        """Test that models are correctly mapped to providers."""
        response = await client.get("/v1/models")
        assert response.status_code == 200

        data = response.json()
        models = data["data"]

        # Create mapping by model ID
        model_by_id = {model["id"]: model for model in models}

        # Test specific provider mappings
        provider_tests = [
            ("gemini-pro", "gemini"),
            ("gpt-4", "openrouter"),
            ("claude-3-opus", "openrouter"),
            ("mistral-small", "openrouter"),
            ("deepseek-r1", "openrouter"),
            ("llama-3.1-8b", "openrouter"),
        ]

        for model_id, expected_provider in provider_tests:
            if model_id in model_by_id:
                assert (
                    model_by_id[model_id]["owned_by"] == expected_provider
                ), f"Model {model_id} should be owned by {expected_provider}"

    async def test_models_endpoint_openai_compatibility(self, client):
        """Test that models endpoint response is OpenAI API compatible."""
        response = await client.get("/v1/models")
        assert response.status_code == 200

        data = response.json()

        # Check top-level structure matches OpenAI API
        assert "object" in data
        assert data["object"] == "list"
        assert "data" in data

        # Check each model has required OpenAI fields
        for model in data["data"]:
            required_fields = [
                "id",
                "object",
                "created",
                "owned_by",
                "permission",
                "root",
                "parent",
            ]
            for field in required_fields:
                assert field in model, f"Required field '{field}' missing from model"

            # Check field types
            assert isinstance(model["id"], str)
            assert model["object"] == "model"
            assert isinstance(model["created"], int)
            assert isinstance(model["owned_by"], str)
            assert isinstance(model["permission"], list)
            assert isinstance(model["root"], str)
            assert model["parent"] is None or isinstance(model["parent"], str)

    async def test_models_endpoint_performance(self, client):
        """Test that models endpoint responds quickly."""
        import time

        start_time = time.time()
        response = await client.get("/v1/models")
        end_time = time.time()

        assert response.status_code == 200

        # Should respond within reasonable time (less than 2 seconds)
        response_time = end_time - start_time
        assert (
            response_time < 2.0
        ), f"Models endpoint took {response_time:.2f}s to respond"


# Content format tests are covered by unit tests in test_api_models.py
# These functional tests focus on end-to-end behavior without external API costs
