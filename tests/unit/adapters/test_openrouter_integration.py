import pytest
import json
from unittest.mock import AsyncMock, MagicMock

from ai_proxy.adapters.openrouter import OpenRouterAdapter


class TestOpenRouterAdapterIntegration:
    """Test cases for OpenRouterAdapter integration functionality."""

    @pytest.mark.asyncio
    async def test_stream_chat_completions_success(self):
        """Test _stream_chat_completions for successful streaming."""
        adapter = OpenRouterAdapter("test_key")

        # Mock streaming response
        mock_response = MagicMock()
        mock_response.status_code = 200

        async def mock_aiter_text():
            yield 'data: {"object": "chat.completion.chunk", "choices": []}\n'
            yield "data: [DONE]\n"

        mock_response.aiter_text = mock_aiter_text

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

        # Should have streamed chunks
        assert len(chunks) > 0

        # Should call client.stream with correct parameters
        adapter.client.stream.assert_called_once_with(
            "POST",
            "/chat/completions",
            json=request_data,
            headers=headers,
            timeout=300.0,
        )

    def test_add_system_fingerprint_to_chunk_valid_json(self):
        """Test _add_system_fingerprint_to_chunk with valid JSON chunk."""
        adapter = OpenRouterAdapter("test_key")

        chunk = 'data: {"object": "chat.completion.chunk", "choices": []}\n\n'
        fingerprint = "fp_test_12345678"

        result = adapter._add_system_fingerprint_to_chunk(chunk, fingerprint)

        # Should add system_fingerprint to the chunk
        assert fingerprint in result

        # Should be valid JSON
        data_line = result.split("\n")[0]
        json_part = data_line[6:]  # Remove 'data: '
        parsed = json.loads(json_part)
        assert parsed["system_fingerprint"] == fingerprint

    def test_add_system_fingerprint_to_chunk_invalid_json(self):
        """Test _add_system_fingerprint_to_chunk with invalid JSON chunk."""
        adapter = OpenRouterAdapter("test_key")

        chunk = "data: invalid json\n\n"
        fingerprint = "fp_test_12345678"

        result = adapter._add_system_fingerprint_to_chunk(chunk, fingerprint)

        # Should return original chunk when JSON is invalid
        assert result == chunk

    def test_add_system_fingerprint_to_chunk_done_message(self):
        """Test _add_system_fingerprint_to_chunk with [DONE] message."""
        adapter = OpenRouterAdapter("test_key")

        chunk = "data: [DONE]\n\n"
        fingerprint = "fp_test_12345678"

        result = adapter._add_system_fingerprint_to_chunk(chunk, fingerprint)

        # Should not modify [DONE] message
        assert result == chunk

    def test_add_system_fingerprint_to_chunk_non_completion_object(self):
        """Test _add_system_fingerprint_to_chunk with non-completion object."""
        adapter = OpenRouterAdapter("test_key")

        chunk = 'data: {"object": "other.object", "data": "test"}\n\n'
        fingerprint = "fp_test_12345678"

        result = adapter._add_system_fingerprint_to_chunk(chunk, fingerprint)

        # Should not add fingerprint to non-completion objects
        assert fingerprint not in result
        assert result == chunk

    def test_add_system_fingerprint_to_chunk_exception(self):
        """Test _add_system_fingerprint_to_chunk when exception occurs."""
        adapter = OpenRouterAdapter("test_key")

        # Create a chunk that will cause an exception during processing
        chunk = None  # This will cause an exception
        fingerprint = "fp_test_12345678"

        result = adapter._add_system_fingerprint_to_chunk(chunk, fingerprint)

        # Should return original chunk when exception occurs
        assert result == chunk

    def test_add_system_fingerprint_to_chunk_multiple_lines(self):
        """Test _add_system_fingerprint_to_chunk with multiple data lines."""
        adapter = OpenRouterAdapter("test_key")

        chunk = 'data: {"object": "chat.completion.chunk", "choices": []}\ndata: {"object": "chat.completion.chunk", "choices": []}\n\n'
        fingerprint = "fp_test_12345678"

        result = adapter._add_system_fingerprint_to_chunk(chunk, fingerprint)

        # Should add fingerprint to both lines
        lines = result.split("\n")
        for line in lines:
            if line.startswith("data: {"):
                json_part = line[6:]
                parsed = json.loads(json_part)
                assert parsed["system_fingerprint"] == fingerprint
