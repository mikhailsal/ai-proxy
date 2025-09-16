import pytest
from unittest.mock import Mock, patch, AsyncMock
import json

from ai_proxy.api.v1.chat_completions import chat_completions_options, chat_completions


class TestChatCompletionsCore:
    """Test suite for chat completions core functionality."""

    @pytest.mark.asyncio
    async def test_chat_completions_options(self):
        """Test CORS preflight response."""
        response = await chat_completions_options()

        assert response.status_code == 200
        assert response.headers["Access-Control-Allow-Origin"] == "*"
        assert response.headers["Access-Control-Allow-Methods"] == "POST, OPTIONS"
        assert (
            response.headers["Access-Control-Allow-Headers"]
            == "Content-Type, Authorization"
        )
        assert response.headers["Access-Control-Max-Age"] == "86400"

    @pytest.fixture
    def mock_request(self):
        """Create a mock request for non-streaming tests."""
        mock_req = Mock()
        mock_req.url.path = "/v1/chat/completions"
        mock_req.json = AsyncMock(
            return_value={
                "model": "gpt-4",
                "messages": [{"role": "user", "content": "Hello"}],
                "stream": False,
            }
        )
        return mock_req

    @pytest.fixture
    def mock_streaming_request(self):
        """Create a mock request for streaming tests."""
        mock_req = Mock()
        mock_req.url.path = "/v1/chat/completions"
        mock_req.json = AsyncMock(
            return_value={
                "model": "gpt-4",
                "messages": [{"role": "user", "content": "Hello"}],
                "stream": True,
            }
        )
        return mock_req

    @patch("ai_proxy.api.v1.chat_completions.routing_router")
    @patch("ai_proxy.api.v1.chat_completions.settings")
    @patch("ai_proxy.api.v1.chat_completions.logger")
    @patch("ai_proxy.api.v1.chat_completions.log_request_response")
    @patch("ai_proxy.api.v1.chat_completions.log_model_usage")
    @patch("ai_proxy.api.v1.chat_completions.time")
    @pytest.mark.asyncio
    async def test_chat_completions_non_streaming_success(
        self,
        mock_time,
        mock_log_model,
        mock_log_request,
        mock_logger,
        mock_settings,
        mock_router,
        mock_request,
    ):
        """Test successful non-streaming chat completion."""
        # Setup mocks
        mock_time.time.side_effect = [1000, 1001]  # start and end times
        mock_settings.get_mapped_model.return_value = ("openai", "gpt-4")

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = '{"choices": [{"message": {"content": "Hello!"}}]}'
        mock_response.json.return_value = {
            "choices": [{"message": {"content": "Hello!"}}]
        }
        mock_router.route_chat_completions = AsyncMock(return_value=mock_response)

        # Execute
        response = await chat_completions(mock_request, "test-api-key")

        # Verify
        assert response.status_code == 200
        mock_router.route_chat_completions.assert_called_once()
        mock_log_request.assert_called_once()
        mock_log_model.assert_called_once()

    @patch("ai_proxy.api.v1.chat_completions.routing_router")
    @patch("ai_proxy.api.v1.chat_completions.settings")
    @patch("ai_proxy.api.v1.chat_completions.logger")
    @patch("ai_proxy.api.v1.chat_completions.log_request_response")
    @patch("ai_proxy.api.v1.chat_completions.log_model_usage")
    @patch("ai_proxy.api.v1.chat_completions.time")
    @pytest.mark.asyncio
    async def test_chat_completions_streaming_success(
        self,
        mock_time,
        mock_log_model,
        mock_log_request,
        mock_logger,
        mock_settings,
        mock_router,
        mock_streaming_request,
    ):
        """Test successful streaming chat completion."""
        # Setup mocks
        mock_time.time.side_effect = [1000, 1001]
        mock_settings.get_mapped_model.return_value = ("openai", "gpt-4")

        async def mock_stream():
            yield 'data: {"id": "test-id", "created": 1234567890, "model": "gpt-4", "choices": [{"index": 0, "delta": {"content": "Hello"}, "finish_reason": null}]}\n\n'
            yield 'data: {"id": "test-id", "created": 1234567890, "model": "gpt-4", "choices": [{"index": 0, "delta": {"content": " world"}, "finish_reason": null}]}\n\n'
            yield 'data: {"id": "test-id", "created": 1234567890, "model": "gpt-4", "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]}\n\n'
            yield "data: [DONE]\n\n"

        mock_router.route_chat_completions = AsyncMock(return_value=mock_stream())

        # Execute
        response = await chat_completions(mock_streaming_request, "test-api-key")

        # Verify
        assert hasattr(response, "body_iterator")  # StreamingResponse
        assert response.media_type == "text/event-stream"

        # Consume the stream to trigger logging
        chunks = []
        async for chunk in response.body_iterator:
            chunks.append(chunk)

        # Verify logging was called
        mock_log_request.assert_called_once()
        mock_log_model.assert_called_once()

    @patch("ai_proxy.api.v1.chat_completions.routing_router")
    @patch("ai_proxy.api.v1.chat_completions.settings")
    @patch("ai_proxy.api.v1.chat_completions.logger")
    @patch("ai_proxy.api.v1.chat_completions.log_request_response")
    @patch("ai_proxy.api.v1.chat_completions.log_model_usage")
    @patch("ai_proxy.api.v1.chat_completions.time")
    @pytest.mark.asyncio
    async def test_chat_completions_model_extraction_from_response(
        self,
        mock_time,
        mock_log_model,
        mock_log_request,
        mock_logger,
        mock_settings,
        mock_router,
        mock_request,
    ):
        """Test model extraction from response body."""
        # Setup mocks
        mock_time.time.side_effect = [1000, 1001]
        mock_settings.get_mapped_model.return_value = ("openai", "gpt-4")

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = (
            '{"model": "gpt-4-turbo", "choices": [{"message": {"content": "Hello!"}}]}'
        )
        mock_response.json.return_value = {
            "model": "gpt-4-turbo",
            "choices": [{"message": {"content": "Hello!"}}],
        }
        mock_router.route_chat_completions = AsyncMock(return_value=mock_response)

        # Execute
        response = await chat_completions(mock_request, "test-api-key")

        # Verify
        assert response.status_code == 200
        # Check that model was extracted from response
        mock_log_model.assert_called_once()
        call_args = mock_log_model.call_args
        assert call_args[1]["mapped_model"] == "gpt-4-turbo"
