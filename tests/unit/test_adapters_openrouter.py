import pytest
import json
from unittest.mock import AsyncMock, MagicMock, patch
import httpx

from ai_proxy.adapters.openrouter import OpenRouterAdapter, OPENROUTER_API_BASE


class TestOpenRouterAdapter:
    """Test cases for the OpenRouterAdapter class."""

    def test_init(self):
        """Test OpenRouterAdapter initialization."""
        adapter = OpenRouterAdapter("test_api_key")
        
        assert adapter.api_key == "test_api_key"
        assert str(adapter.client.base_url).rstrip('/') == OPENROUTER_API_BASE
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
            "choices": [{"message": {"role": "assistant", "content": "Hello!"}}]
        }
        
        # Mock the client response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = response_data
        
        adapter.client.post = AsyncMock(return_value=mock_response)
        
        request_data = {
            "model": "gpt-4",
            "messages": [{"role": "user", "content": "Hello"}],
            "stream": False
        }
        
        result = await adapter.chat_completions(request_data)
        
        # Should call client.post with correct parameters
        adapter.client.post.assert_called_once_with(
            "/chat/completions",
            json=request_data,
            headers={
                "HTTP-Referer": "http://localhost:8123",
                "X-Title": "AI Proxy"
            },
            timeout=300.0
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
            "stream": False
        }
        
        result = await adapter.chat_completions(request_data)
        
        # Should return the error response as-is
        assert result == mock_response

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
            "stream": False
        }
        
        result = await adapter.chat_completions(request_data)
        
        # Should return original response when JSON decode fails
        assert result == mock_response
    
    @pytest.mark.asyncio
    async def test_chat_completions_non_streaming_key_error(self):
        """Test chat_completions when response has missing keys."""
        adapter = OpenRouterAdapter("test_key")
        
        # Mock response with missing model key to trigger KeyError
        response_data = {
            "id": "chatcmpl-123",
            "object": "chat.completion",
            # Missing "model" key
            "choices": [{"message": {"role": "assistant", "content": "Hello!"}}]
        }
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        # Make json() method raise KeyError to trigger the exception handling
        mock_response.json.side_effect = KeyError("model")
        
        adapter.client.post = AsyncMock(return_value=mock_response)
        
        request_data = {
            "model": "gpt-4",
            "messages": [{"role": "user", "content": "Hello"}],
            "stream": False
        }
        
        result = await adapter.chat_completions(request_data)
        
        # Should return original response when KeyError occurs during JSON parsing
        # The implementation catches KeyError and returns the original response
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
            "stream": True
        }
        
        result = await adapter.chat_completions(request_data)
        
        # Since we replaced the method, we can't assert on calls
        # Just verify the result is an async generator
        
        # Should return the async generator
        assert hasattr(result, '__aiter__')

    @pytest.mark.asyncio
    async def test_stream_chat_completions_success(self):
        """Test _stream_chat_completions for successful streaming."""
        adapter = OpenRouterAdapter("test_key")
        
        # Mock streaming response
        mock_response = MagicMock()
        mock_response.status_code = 200
        
        async def mock_aiter_text():
            yield "data: {\"object\": \"chat.completion.chunk\", \"choices\": []}\n"
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
            timeout=300.0
        )

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
        adapter.client.stream = MagicMock(side_effect=httpx.RequestError("Connection failed"))
        
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

    def test_add_system_fingerprint_to_chunk_valid_json(self):
        """Test _add_system_fingerprint_to_chunk with valid JSON chunk."""
        adapter = OpenRouterAdapter("test_key")
        
        chunk = 'data: {"object": "chat.completion.chunk", "choices": []}\n\n'
        fingerprint = "fp_test_12345678"
        
        result = adapter._add_system_fingerprint_to_chunk(chunk, fingerprint)
        
        # Should add system_fingerprint to the chunk
        assert fingerprint in result
        
        # Should be valid JSON
        data_line = result.split('\n')[0]
        json_part = data_line[6:]  # Remove 'data: '
        parsed = json.loads(json_part)
        assert parsed["system_fingerprint"] == fingerprint

    def test_add_system_fingerprint_to_chunk_invalid_json(self):
        """Test _add_system_fingerprint_to_chunk with invalid JSON chunk."""
        adapter = OpenRouterAdapter("test_key")
        
        chunk = 'data: invalid json\n\n'
        fingerprint = "fp_test_12345678"
        
        result = adapter._add_system_fingerprint_to_chunk(chunk, fingerprint)
        
        # Should return original chunk when JSON is invalid
        assert result == chunk

    def test_add_system_fingerprint_to_chunk_done_message(self):
        """Test _add_system_fingerprint_to_chunk with [DONE] message."""
        adapter = OpenRouterAdapter("test_key")
        
        chunk = 'data: [DONE]\n\n'
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
        lines = result.split('\n')
        for line in lines:
            if line.startswith('data: {'):
                json_part = line[6:]
                parsed = json.loads(json_part)
                assert parsed["system_fingerprint"] == fingerprint 