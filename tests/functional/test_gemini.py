"""
Functional tests for Gemini API provider.

These tests verify Gemini-specific functionality by making actual HTTP requests
to the AI proxy service, which then routes to Google Gemini API.

⚠️  WARNING: These tests consume real API quotas and may incur costs!
    They are disabled by default and should only be run when explicitly enabled.
"""

import asyncio
import os
import pytest
import pytest_asyncio
import httpx

pytestmark = [pytest.mark.asyncio]


class TestGeminiFunctionality:
    """Test Gemini-specific API functionality with actual external service calls."""

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

    async def test_health_endpoint(self, client):
        """Test that health endpoint is accessible."""
        response = await client.get("/health")
        assert response.status_code == 200

        data = response.json()
        assert data["status"] == "ok"
        assert "version" in data

    async def test_gemini_chat_completion(self, client, api_key):
        """Test real Gemini API call through proxy."""
        if not os.getenv("GEMINI_API_KEY"):
            pytest.skip("GEMINI_API_KEY not set")

        payload = {
            "model": "gemini-pro",
            "messages": [
                {"role": "user", "content": "Say 'Hello from Gemini' and nothing else."}
            ],
            "max_tokens": 10,
            "temperature": 0.1,
        }

        response = await client.post(
            "/v1/chat/completions",
            json=payload,
            headers={"Authorization": f"Bearer {api_key}"},
        )

        assert response.status_code == 200
        data = response.json()

        # Verify response structure
        assert "choices" in data
        assert len(data["choices"]) > 0
        assert "message" in data["choices"][0]
        assert "content" in data["choices"][0]["message"]

        # Verify content is not empty
        content = data["choices"][0]["message"]["content"]
        assert content.strip(), "Response content should not be empty"

    async def test_gemini_streaming_chat_completion(self, client, api_key):
        """Test real Gemini streaming API call through proxy."""
        if not os.getenv("GEMINI_API_KEY"):
            pytest.skip("GEMINI_API_KEY not set")

        payload = {
            "model": "gemini-pro",
            "messages": [
                {
                    "role": "user",
                    "content": "Count from 1 to 3, each number on a new line.",
                }
            ],
            "stream": True,
            "max_tokens": 20,
            "temperature": 0.1,
        }

        response = await client.post(
            "/v1/chat/completions",
            json=payload,
            headers={"Authorization": f"Bearer {api_key}"},
        )

        assert response.status_code == 200
        assert response.headers.get("content-type") == "text/event-stream"

        # Collect streaming chunks
        chunks = []
        async for chunk in response.aiter_lines():
            if chunk.strip():
                chunks.append(chunk)
                # Limit chunks to avoid infinite streams
                if len(chunks) > 20:
                    break

        # Verify we received streaming data
        assert len(chunks) > 0, "Should receive streaming chunks"


class TestGeminiEdgeCases:
    """Test Gemini-specific edge cases and error conditions."""

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

    async def test_gemini_model_mapping_consistency(self, client, api_key):
        """Test that Gemini model mappings work consistently."""
        # Test different Gemini model aliases
        test_models = ["gemini-pro", "gemini-flash", "gemini-2.0-flash"]

        if not os.getenv("GEMINI_API_KEY"):
            pytest.skip("GEMINI_API_KEY not set")

        results = []
        for model in test_models:
            payload = {
                "model": model,
                "messages": [{"role": "user", "content": "Say 'OK' and nothing else."}],
                "max_tokens": 5,
                "temperature": 0.1,
            }

            response = await client.post(
                "/v1/chat/completions",
                json=payload,
                headers={"Authorization": f"Bearer {api_key}"},
            )

            assert response.status_code == 200
            data = response.json()
            assert "choices" in data
            results.append(data)

        # All should have succeeded
        assert len(results) == len(test_models)


class TestGeminiPerformanceAndReliability:
    """Test Gemini performance and reliability aspects."""

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
        async with httpx.AsyncClient(base_url=base_url, timeout=60.0) as client:
            yield client

    async def test_gemini_concurrent_requests(self, client, api_key):
        """Test handling of concurrent Gemini requests."""
        if not os.getenv("GEMINI_API_KEY"):
            pytest.skip("GEMINI_API_KEY not set")

        async def make_request(request_id: int):
            payload = {
                "model": "gemini-pro",
                "messages": [
                    {
                        "role": "user",
                        "content": f"Say 'Request {request_id}' and nothing else.",
                    }
                ],
                "max_tokens": 10,
                "temperature": 0.1,
            }

            response = await client.post(
                "/v1/chat/completions",
                json=payload,
                headers={"Authorization": f"Bearer {api_key}"},
            )
            return response

        # Make 3 concurrent requests
        tasks = [make_request(i) for i in range(3)]
        responses = await asyncio.gather(*tasks, return_exceptions=True)

        # Check that all requests succeeded
        successful_responses = 0
        for response in responses:
            if isinstance(response, httpx.Response) and response.status_code == 200:
                successful_responses += 1

        # At least 2 out of 3 should succeed (allowing for rate limiting)
        assert successful_responses >= 2, (
            f"Only {successful_responses} out of 3 requests succeeded"
        )

    async def test_gemini_request_timeout_handling(self, client, api_key):
        """Test that Gemini requests don't hang indefinitely."""
        if not os.getenv("GEMINI_API_KEY"):
            pytest.skip("GEMINI_API_KEY not set")

        payload = {
            "model": "gemini-pro",
            "messages": [
                {"role": "user", "content": "Write a short haiku about programming."}
            ],
            "max_tokens": 50,
            "temperature": 0.7,
        }

        # This should complete within reasonable time
        response = await client.post(
            "/v1/chat/completions",
            json=payload,
            headers={"Authorization": f"Bearer {api_key}"},
        )

        assert response.status_code == 200
        data = response.json()
        assert "choices" in data
        assert len(data["choices"]) > 0

    async def test_gemini_empty_message_content(self, client, api_key):
        """Test Gemini handling of empty message content."""
        if not os.getenv("GEMINI_API_KEY"):
            pytest.skip("GEMINI_API_KEY not set")

        payload = {
            "model": "gemini-pro",
            "messages": [{"role": "user", "content": ""}],
            "max_tokens": 10,
        }

        response = await client.post(
            "/v1/chat/completions",
            json=payload,
            headers={"Authorization": f"Bearer {api_key}"},
        )

        # Should handle gracefully (either succeed or return meaningful error)
        assert response.status_code in [200, 400]

    async def test_gemini_very_long_message(self, client, api_key):
        """Test Gemini handling of very long message content."""
        if not os.getenv("GEMINI_API_KEY"):
            pytest.skip("GEMINI_API_KEY not set")

        # Create a very long message
        long_content = "Please summarize this text: " + "A" * 1000

        payload = {
            "model": "gemini-pro",
            "messages": [{"role": "user", "content": long_content}],
            "max_tokens": 50,
        }

        response = await client.post(
            "/v1/chat/completions",
            json=payload,
            headers={"Authorization": f"Bearer {api_key}"},
        )

        # Should handle gracefully
        assert response.status_code in [200, 400, 413]

    async def test_gemini_special_characters_in_message(self, client, api_key):
        """Test Gemini handling of special characters in message content."""
        if not os.getenv("GEMINI_API_KEY"):
            pytest.skip("GEMINI_API_KEY not set")

        special_content = "Test with special chars: 🚀 ñáéíóú 中文 العربية \n\t\r"

        payload = {
            "model": "gemini-pro",
            "messages": [{"role": "user", "content": special_content}],
            "max_tokens": 20,
        }

        response = await client.post(
            "/v1/chat/completions",
            json=payload,
            headers={"Authorization": f"Bearer {api_key}"},
        )

        assert response.status_code == 200
        data = response.json()
        assert "choices" in data
