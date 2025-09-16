import pytest
import json
from unittest.mock import AsyncMock, MagicMock
import httpx

from ai_proxy.adapters.openrouter import OpenRouterAdapter, OPENROUTER_API_BASE


class TestOpenRouterAdapterCore:
    """Test cases for core OpenRouterAdapter functionality."""

    def test_init(self):
        """Test OpenRouterAdapter initialization."""
        adapter = OpenRouterAdapter("test_api_key")

        assert adapter.api_key == "test_api_key"
        assert str(adapter.client.base_url).rstrip("/") == OPENROUTER_API_BASE
        assert adapter.client.headers["Authorization"] == "Bearer test_api_key"
        assert adapter.client.headers["Content-Type"] == "application/json"

    def test_generate_system_fingerprint(self):
        """Test _generate_system_fingerprint method."""
        adapter = OpenRouterAdapter("test_key")

        fingerprint1 = adapter._generate_system_fingerprint("gpt-4")
        fingerprint2 = adapter._generate_system_fingerprint("gpt-4")
        fingerprint3 = adapter._generate_system_fingerprint("claude-3")

        # Same model should generate same fingerprint
        assert fingerprint1 == fingerprint2

        # Different models should generate different fingerprints
        assert fingerprint1 != fingerprint3

        # Should start with expected prefix
        assert fingerprint1.startswith("fp_openrouter_")
        assert len(fingerprint1) == len("fp_openrouter_") + 8  # 8 hex chars

    @pytest.mark.asyncio
    async def test_chat_completions_non_streaming_success(self):
        """Test chat_completions for non-streaming successful request."""
        adapter = OpenRouterAdapter("test_key")

        # Mock response data
        response_data = {
            "id": "chatcmpl-123",
            "object": "chat.completion",
            "model": "gpt-4",
            "choices": [{"message": {"role": "assistant", "content": "Hello!"}}],
        }

        # Mock the client response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = response_data

        adapter.client.post = AsyncMock(return_value=mock_response)

        request_data = {
            "model": "gpt-4",
            "messages": [{"role": "user", "content": "Hello"}],
            "stream": False,
        }

        result = await adapter.chat_completions(request_data)

        # Should call client.post with correct parameters
        adapter.client.post.assert_called_once_with(
            "/chat/completions",
            json=request_data,
            headers={"HTTP-Referer": "http://localhost:8123", "X-Title": "AI Proxy"},
            timeout=300.0,
        )

        # Should return modified response with system_fingerprint
        assert isinstance(result, httpx.Response)
        assert result.status_code == 200

        # Check that system_fingerprint was added
        result_data = json.loads(result.content.decode())
        assert "system_fingerprint" in result_data
        assert result_data["system_fingerprint"].startswith("fp_openrouter_")

    @pytest.mark.asyncio
    async def test_chat_completions_non_streaming_error(self):
        """Test chat_completions for non-streaming error response."""
        adapter = OpenRouterAdapter("test_key")

        # Mock error response
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.json.return_value = {"error": {"message": "Bad request"}}

        adapter.client.post = AsyncMock(return_value=mock_response)

        request_data = {
            "model": "gpt-4",
            "messages": [{"role": "user", "content": "Hello"}],
            "stream": False,
        }

        result = await adapter.chat_completions(request_data)

        # Should return the error response as-is
        assert result == mock_response

    @pytest.mark.asyncio
    async def test_chat_completions_streaming(self):
        """Test chat_completions for streaming request."""
        adapter = OpenRouterAdapter("test_key")

        # Mock the streaming method to return an actual async generator
        async def mock_stream(request_data, headers):
            yield "data: chunk1"
            yield "data: chunk2"

        # Replace the method directly
        adapter._stream_chat_completions = mock_stream

        request_data = {
            "model": "gpt-4",
            "messages": [{"role": "user", "content": "Hello"}],
            "stream": True,
        }

        result = await adapter.chat_completions(request_data)

        # Since we replaced the method, we can't assert on calls
        # Just verify the result is an async generator

        # Should return the async generator
        assert hasattr(result, "__aiter__")
