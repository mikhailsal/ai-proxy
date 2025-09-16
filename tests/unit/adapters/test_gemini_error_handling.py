import pytest
from unittest.mock import patch, AsyncMock
import json

from ai_proxy.adapters.gemini import GeminiAdapter
from google.genai import types


class TestGeminiAdapterErrorHandling:
    """Test suite for GeminiAdapter error handling scenarios."""

    @pytest.fixture
    def gemini_adapter(self):
        """Create GeminiAdapter instance for testing."""
        with patch("ai_proxy.adapters.gemini.genai.Client") as mock_client:
            adapter = GeminiAdapter("test-api-key")
            adapter.gemini_client = mock_client.return_value
            return adapter

    @pytest.fixture
    def openai_request(self):
        """Sample OpenAI format request."""
        return {
            "model": "gemini-pro",
            "messages": [{"role": "user", "content": "Hello"}],
            "stream": False,
        }

    @pytest.mark.asyncio
    async def test_chat_completions_exception_handling(
        self, gemini_adapter, openai_request
    ):
        """Test exception handling in chat_completions."""
        with patch.object(
            gemini_adapter,
            "_convert_openai_to_gemini",
            side_effect=Exception("Test error"),
        ):
            result = await gemini_adapter.chat_completions(openai_request)
            assert result.status_code == 500
            response_data = json.loads(result.content)
            assert "error" in response_data
            assert response_data["error"]["message"] == "Test error"

    @pytest.mark.asyncio
    async def test_handle_non_streaming_response_exception(self, gemini_adapter):
        """Test exception handling in non-streaming response."""
        gemini_request = {
            "model": "gemini-pro",
            "contents": [
                types.Content(role="user", parts=[types.Part.from_text(text="Hello")])
            ],
        }

        # Create async mock that raises exception
        async_mock = AsyncMock(side_effect=Exception("API error"))

        with patch.object(
            gemini_adapter.gemini_client.aio.models, "generate_content", async_mock
        ):
            with pytest.raises(Exception, match="API error"):
                await gemini_adapter._handle_non_streaming_response(gemini_request, {})

    @pytest.mark.asyncio
    async def test_stream_chat_completions_exception_openai_format(
        self, gemini_adapter
    ):
        """Test streaming exception handling with OpenAI format."""
        gemini_request = {
            "model": "gemini-pro",
            "contents": [
                types.Content(role="user", parts=[types.Part.from_text(text="Hello")])
            ],
        }

        with patch("ai_proxy.adapters.gemini.settings.gemini_as_is", False):
            with patch.object(
                gemini_adapter.gemini_client.aio.models,
                "generate_content_stream",
                AsyncMock(side_effect=Exception("Stream error")),
            ):
                result = gemini_adapter._stream_chat_completions(gemini_request, {})

                chunks = []
                async for chunk in result:
                    chunks.append(chunk)

                # Should have error chunk
                assert len(chunks) >= 1
                assert any("error" in chunk for chunk in chunks)

    @pytest.mark.asyncio
    async def test_stream_chat_completions_exception_gemini_as_is(self, gemini_adapter):
        """Test streaming exception handling with Gemini raw format."""
        gemini_request = {
            "model": "gemini-pro",
            "contents": [
                types.Content(role="user", parts=[types.Part.from_text(text="Hello")])
            ],
        }

        with patch("ai_proxy.adapters.gemini.settings.gemini_as_is", True):
            with patch.object(
                gemini_adapter.gemini_client.aio.models,
                "generate_content_stream",
                AsyncMock(side_effect=Exception("Stream error")),
            ):
                result = gemini_adapter._stream_chat_completions(gemini_request, {})

                chunks = []
                async for chunk in result:
                    chunks.append(chunk)

                # Should have error chunk in Gemini format
                assert len(chunks) == 2  # error chunk + DONE
                assert "Stream error" in chunks[0]
                assert "data: [DONE]" in chunks[-1]
