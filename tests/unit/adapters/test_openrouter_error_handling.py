import pytest
import json
from unittest.mock import AsyncMock, MagicMock
import httpx

from ai_proxy.adapters.openrouter import OpenRouterAdapter


class TestOpenRouterAdapterErrorHandling:
    """Test cases for OpenRouterAdapter error handling."""

    @pytest.mark.asyncio
    async def test_chat_completions_non_streaming_json_decode_error(self):
        """Test chat_completions when response JSON can't be decoded."""
        adapter = OpenRouterAdapter("test_key")

        # Mock response that can't be JSON decoded
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.side_effect = json.JSONDecodeError("Invalid JSON", "", 0)

        adapter.client.post = AsyncMock(return_value=mock_response)

        request_data = {
            "model": "gpt-4",
            "messages": [{"role": "user", "content": "Hello"}],
            "stream": False,
        }

        result = await adapter.chat_completions(request_data)

        # Should return original response when JSON decode fails
        assert result == mock_response

    @pytest.mark.asyncio
    async def test_chat_completions_non_streaming_key_error(self):
        """Test chat_completions when response has missing keys."""
        adapter = OpenRouterAdapter("test_key")

        # Mock response with missing model key to trigger KeyError
        mock_response = MagicMock()
        mock_response.status_code = 200
        # Make json() method raise KeyError to trigger the exception handling
        mock_response.json.side_effect = KeyError("model")

        adapter.client.post = AsyncMock(return_value=mock_response)

        request_data = {
            "model": "gpt-4",
            "messages": [{"role": "user", "content": "Hello"}],
            "stream": False,
        }

        result = await adapter.chat_completions(request_data)

        # Should return original response when KeyError occurs during JSON parsing
        # The implementation catches KeyError and returns the original response
        assert result == mock_response

    @pytest.mark.asyncio
    async def test_stream_chat_completions_http_error(self):
        """Test _stream_chat_completions for HTTP error response."""
        adapter = OpenRouterAdapter("test_key")

        # Mock error response
        mock_response = MagicMock()
        mock_response.status_code = 400

        # Make aread return a coroutine
        async def mock_aread():
            return b'{"error": {"message": "Bad request"}}'

        mock_response.aread = mock_aread

        # Mock the context manager
        mock_stream_context = AsyncMock()
        mock_stream_context.__aenter__.return_value = mock_response
        mock_stream_context.__aexit__.return_value = None

        adapter.client.stream = MagicMock(return_value=mock_stream_context)

        request_data = {"model": "gpt-4", "messages": []}
        headers = {"test": "header"}

        chunks = []
        async for chunk in adapter._stream_chat_completions(request_data, headers):
            chunks.append(chunk)

        # Should yield error chunk
        assert len(chunks) == 1
        assert "error" in chunks[0]
        assert "Bad request" in chunks[0]
        assert "[DONE]" in chunks[0]

    @pytest.mark.asyncio
    async def test_stream_chat_completions_timeout(self):
        """Test _stream_chat_completions for timeout error."""
        adapter = OpenRouterAdapter("test_key")

        # Mock timeout exception
        adapter.client.stream = MagicMock(side_effect=httpx.TimeoutException("Timeout"))

        request_data = {"model": "gpt-4", "messages": []}
        headers = {"test": "header"}

        chunks = []
        async for chunk in adapter._stream_chat_completions(request_data, headers):
            chunks.append(chunk)

        # Should yield timeout error chunk
        assert len(chunks) == 1
        assert "Request timeout" in chunks[0]
        assert "408" in chunks[0]
        assert "[DONE]" in chunks[0]

    @pytest.mark.asyncio
    async def test_stream_chat_completions_request_error(self):
        """Test _stream_chat_completions for request error."""
        adapter = OpenRouterAdapter("test_key")

        # Mock request exception
        adapter.client.stream = MagicMock(
            side_effect=httpx.RequestError("Connection failed")
        )

        request_data = {"model": "gpt-4", "messages": []}
        headers = {"test": "header"}

        chunks = []
        async for chunk in adapter._stream_chat_completions(request_data, headers):
            chunks.append(chunk)

        # Should yield connection error chunk
        assert len(chunks) == 1
        assert "Connection error" in chunks[0]
        assert "502" in chunks[0]
        assert "[DONE]" in chunks[0]

    @pytest.mark.asyncio
    async def test_stream_chat_completions_general_exception(self):
        """Test _stream_chat_completions for general exception."""
        adapter = OpenRouterAdapter("test_key")

        # Mock general exception
        adapter.client.stream = MagicMock(side_effect=Exception("General error"))

        request_data = {"model": "gpt-4", "messages": []}
        headers = {"test": "header"}

        chunks = []
        async for chunk in adapter._stream_chat_completions(request_data, headers):
            chunks.append(chunk)

        # Should yield streaming error chunk
        assert len(chunks) == 1
        assert "Streaming error" in chunks[0]
        assert "500" in chunks[0]
        assert "[DONE]" in chunks[0]
