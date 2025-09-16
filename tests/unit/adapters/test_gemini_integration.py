import pytest
from unittest.mock import Mock, patch, AsyncMock
import json
import httpx

from ai_proxy.adapters.gemini import GeminiAdapter
from google.genai import types


class TestGeminiAdapterIntegration:
    """Test suite for GeminiAdapter integration scenarios."""

    @pytest.fixture
    def gemini_adapter(self):
        """Create GeminiAdapter instance for testing."""
        with patch("ai_proxy.adapters.gemini.genai.Client") as mock_client:
            adapter = GeminiAdapter("test-api-key")
            adapter.gemini_client = mock_client.return_value
            return adapter

    @pytest.mark.asyncio
    async def test_handle_non_streaming_response_with_gemini_as_is(
        self, gemini_adapter
    ):
        """Test non-streaming response with GEMINI_AS_IS enabled."""
        gemini_request = {
            "model": "gemini-pro",
            "contents": [
                types.Content(role="user", parts=[types.Part.from_text(text="Hello")])
            ],
        }

        # Mock Gemini response
        mock_gemini_response = Mock()
        mock_gemini_response.text = "Hello there!"

        # Create async mock
        async_mock = AsyncMock(return_value=mock_gemini_response)

        with patch("ai_proxy.adapters.gemini.settings.gemini_as_is", True):
            with patch.object(
                gemini_adapter.gemini_client.aio.models, "generate_content", async_mock
            ):
                result = await gemini_adapter._handle_non_streaming_response(
                    gemini_request, {}
                )

                assert isinstance(result, httpx.Response)
                assert result.status_code == 200
                response_data = json.loads(result.content)
                assert response_data["text"] == "Hello there!"
                assert response_data["model"] == "gemini-pro"

    @pytest.mark.asyncio
    async def test_stream_chat_completions_openai_format(self, gemini_adapter):
        """Test streaming with OpenAI format output."""
        gemini_request = {
            "model": "gemini-pro",
            "contents": [
                types.Content(role="user", parts=[types.Part.from_text(text="Hello")])
            ],
        }

        # Mock streaming response
        async def mock_stream():
            chunk1 = Mock()
            chunk1.text = "Hello"
            chunk2 = Mock()
            chunk2.text = " there!"
            for chunk in [chunk1, chunk2]:
                yield chunk

        with patch("ai_proxy.adapters.gemini.settings.gemini_as_is", False):
            with patch.object(
                gemini_adapter.gemini_client.aio.models,
                "generate_content_stream",
                AsyncMock(return_value=mock_stream()),
            ):
                result = gemini_adapter._stream_chat_completions(gemini_request, {})

                chunks = []
                async for chunk in result:
                    chunks.append(chunk)

                # Should have chunks with content plus final chunk
                assert len(chunks) >= 2
                assert "Hello" in chunks[0] or "Hello" in chunks[1]
                assert "data: [DONE]" in chunks[-1]

    @pytest.mark.asyncio
    async def test_stream_chat_completions_gemini_as_is(self, gemini_adapter):
        """Test streaming with Gemini raw format output."""
        gemini_request = {
            "model": "gemini-pro",
            "contents": [
                types.Content(role="user", parts=[types.Part.from_text(text="Hello")])
            ],
        }

        # Mock streaming response
        async def mock_stream():
            chunk = Mock()
            chunk.text = "Hello there!"
            yield chunk

        with patch("ai_proxy.adapters.gemini.settings.gemini_as_is", True):
            with patch.object(
                gemini_adapter.gemini_client.aio.models,
                "generate_content_stream",
                AsyncMock(return_value=mock_stream()),
            ):
                result = gemini_adapter._stream_chat_completions(gemini_request, {})

                chunks = []
                async for chunk in result:
                    chunks.append(chunk)

                assert len(chunks) == 2  # content chunk + DONE
                assert "Hello there!" in chunks[0]
                assert "data: [DONE]" in chunks[1]

    @pytest.mark.asyncio
    async def test_stream_chat_completions_empty_chunks(self, gemini_adapter):
        """Test streaming with empty chunks."""
        gemini_request = {
            "model": "gemini-pro",
            "contents": [
                types.Content(role="user", parts=[types.Part.from_text(text="Hello")])
            ],
        }

        # Mock streaming response with empty chunks
        async def mock_stream():
            chunk1 = Mock()
            chunk1.text = None  # Empty chunk
            chunk2 = Mock()
            chunk2.text = "Hello"
            for chunk in [chunk1, chunk2]:
                yield chunk

        with patch("ai_proxy.adapters.gemini.settings.gemini_as_is", False):
            with patch.object(
                gemini_adapter.gemini_client.aio.models,
                "generate_content_stream",
                AsyncMock(return_value=mock_stream()),
            ):
                result = gemini_adapter._stream_chat_completions(gemini_request, {})

                chunks = []
                async for chunk in result:
                    chunks.append(chunk)

                # Should handle empty chunks gracefully
                assert len(chunks) >= 2
                assert "data: [DONE]" in chunks[-1]
