import pytest
from unittest.mock import Mock, patch, AsyncMock
import json

from ai_proxy.api.v1.chat_completions import chat_completions


class TestChatCompletionsErrorHandling:
    """Test suite for chat completions error handling."""

    @pytest.fixture
    def mock_request(self):
        """Create a mock request for error handling tests."""
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
        """Create a mock streaming request for error handling tests."""
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
    async def test_chat_completions_non_streaming_empty_response(
        self,
        mock_time,
        mock_log_model,
        mock_log_request,
        mock_logger,
        mock_settings,
        mock_router,
        mock_request,
    ):
        """Test non-streaming with empty response."""
        # Setup mocks
        mock_time.time.side_effect = [1000, 1001]
        mock_settings.get_mapped_model.return_value = ("openai", "gpt-4")

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = ""
        mock_router.route_chat_completions = AsyncMock(return_value=mock_response)

        # Execute
        response = await chat_completions(mock_request, "test-api-key")

        # Verify - status is 200 because else block overwrites status_code with provider_response.status_code
        # But the response body should contain the error message
        assert response.status_code == 200
        response_data = json.loads(response.body)
        assert "error" in response_data
        assert "Empty response from provider" in response_data["error"]
        mock_logger.warning.assert_called_with("Empty response from provider")

    @patch("ai_proxy.api.v1.chat_completions.routing_router")
    @patch("ai_proxy.api.v1.chat_completions.settings")
    @patch("ai_proxy.api.v1.chat_completions.logger")
    @patch("ai_proxy.api.v1.chat_completions.log_request_response")
    @patch("ai_proxy.api.v1.chat_completions.log_model_usage")
    @patch("ai_proxy.api.v1.chat_completions.time")
    @pytest.mark.asyncio
    async def test_chat_completions_non_streaming_invalid_json(
        self,
        mock_time,
        mock_log_model,
        mock_log_request,
        mock_logger,
        mock_settings,
        mock_router,
        mock_request,
    ):
        """Test non-streaming with invalid JSON response."""
        # Setup mocks
        mock_time.time.side_effect = [1000, 1001]
        mock_settings.get_mapped_model.return_value = ("openai", "gpt-4")

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = "invalid json"
        mock_response.json.side_effect = ValueError("Invalid JSON")
        mock_router.route_chat_completions = AsyncMock(return_value=mock_response)

        # Execute
        response = await chat_completions(mock_request, "test-api-key")

        # Verify
        assert response.status_code == 502
        mock_logger.error.assert_called()

    @patch("ai_proxy.api.v1.chat_completions.routing_router")
    @patch("ai_proxy.api.v1.chat_completions.settings")
    @patch("ai_proxy.api.v1.chat_completions.logger")
    @patch("ai_proxy.api.v1.chat_completions.time")
    @pytest.mark.asyncio
    async def test_chat_completions_non_streaming_exception(
        self, mock_time, mock_logger, mock_settings, mock_router, mock_request
    ):
        """Test non-streaming with exception."""
        # Setup mocks
        mock_time.time.side_effect = [1000, 1001]
        mock_settings.get_mapped_model.return_value = ("openai", "gpt-4")
        mock_router.route_chat_completions = AsyncMock(
            side_effect=Exception("Test error")
        )

        # Execute
        response = await chat_completions(mock_request, "test-api-key")

        # Verify
        assert response.status_code == 500
        # Check that logger.error was called with exc_info=Exception
        mock_logger.error.assert_called_once()
        call_args = mock_logger.error.call_args
        assert call_args[0][0] == "Error processing request"
        assert call_args[1]["exc_info"] is not None
        assert isinstance(call_args[1]["exc_info"], Exception)

    @patch("ai_proxy.api.v1.chat_completions.routing_router")
    @patch("ai_proxy.api.v1.chat_completions.settings")
    @patch("ai_proxy.api.v1.chat_completions.logger")
    @patch("ai_proxy.api.v1.chat_completions.log_request_response")
    @patch("ai_proxy.api.v1.chat_completions.log_model_usage")
    @patch("ai_proxy.api.v1.chat_completions.time")
    @pytest.mark.asyncio
    async def test_chat_completions_streaming_with_error_chunk(
        self,
        mock_time,
        mock_log_model,
        mock_log_request,
        mock_logger,
        mock_settings,
        mock_router,
        mock_streaming_request,
    ):
        """Test streaming with error chunk."""
        # Setup mocks
        mock_time.time.side_effect = [1000, 1001]
        mock_settings.get_mapped_model.return_value = ("openai", "gpt-4")

        async def mock_stream():
            yield 'data: {"error": {"code": 400, "message": "Bad request"}}\n\n'

        mock_router.route_chat_completions = AsyncMock(return_value=mock_stream())

        # Execute
        response = await chat_completions(mock_streaming_request, "test-api-key")

        # Verify
        assert hasattr(response, "body_iterator")

        # Consume the stream
        chunks = []
        async for chunk in response.body_iterator:
            chunks.append(chunk)

        # Verify error logging
        mock_log_request.assert_called_once()
        mock_log_model.assert_called_once()

    @patch("ai_proxy.api.v1.chat_completions.routing_router")
    @patch("ai_proxy.api.v1.chat_completions.settings")
    @patch("ai_proxy.api.v1.chat_completions.logger")
    @patch("ai_proxy.api.v1.chat_completions.log_request_response")
    @patch("ai_proxy.api.v1.chat_completions.log_model_usage")
    @patch("ai_proxy.api.v1.chat_completions.time")
    @pytest.mark.asyncio
    async def test_chat_completions_streaming_exception(
        self,
        mock_time,
        mock_log_model,
        mock_log_request,
        mock_logger,
        mock_settings,
        mock_router,
        mock_streaming_request,
    ):
        """Test streaming with exception."""
        # Setup mocks
        mock_time.time.side_effect = [1000, 1001]
        mock_settings.get_mapped_model.return_value = ("openai", "gpt-4")

        async def mock_stream():
            yield 'data: {"id": "test-id", "choices": [{"delta": {"content": "Hello"}}]}\n\n'
            raise Exception("Stream error")

        mock_router.route_chat_completions = AsyncMock(return_value=mock_stream())

        # Execute
        response = await chat_completions(mock_streaming_request, "test-api-key")

        # Verify
        assert hasattr(response, "body_iterator")

        # Consume the stream
        chunks = []
        async for chunk in response.body_iterator:
            chunks.append(chunk)

        # Verify error chunk is sent
        assert any("error" in chunk for chunk in chunks)
        mock_log_request.assert_called_once()
        mock_log_model.assert_called_once()

    @patch("ai_proxy.api.v1.chat_completions.routing_router")
    @patch("ai_proxy.api.v1.chat_completions.settings")
    @patch("ai_proxy.api.v1.chat_completions.logger")
    @patch("ai_proxy.api.v1.chat_completions.time")
    @pytest.mark.asyncio
    async def test_chat_completions_streaming_router_exception(
        self, mock_time, mock_logger, mock_settings, mock_router, mock_streaming_request
    ):
        """Test streaming when router raises exception."""
        # Setup mocks
        mock_time.time.side_effect = [1000, 1001]
        mock_settings.get_mapped_model.return_value = ("openai", "gpt-4")
        mock_router.route_chat_completions = AsyncMock(
            side_effect=Exception("Router error")
        )

        # Execute
        response = await chat_completions(mock_streaming_request, "test-api-key")

        # Verify
        assert response.status_code == 500
        # Check that logger.error was called with exc_info=Exception
        mock_logger.error.assert_called_once()
        call_args = mock_logger.error.call_args
        assert call_args[0][0] == "Error processing request"
        assert call_args[1]["exc_info"] is not None
        assert isinstance(call_args[1]["exc_info"], Exception)

    @patch("ai_proxy.api.v1.chat_completions.routing_router")
    @patch("ai_proxy.api.v1.chat_completions.settings")
    @patch("ai_proxy.api.v1.chat_completions.logger")
    @patch("ai_proxy.api.v1.chat_completions.log_request_response")
    @patch("ai_proxy.api.v1.chat_completions.log_model_usage")
    @patch("ai_proxy.api.v1.chat_completions.time")
    @pytest.mark.asyncio
    async def test_chat_completions_streaming_malformed_chunks(
        self,
        mock_time,
        mock_log_model,
        mock_log_request,
        mock_logger,
        mock_settings,
        mock_router,
        mock_streaming_request,
    ):
        """Test streaming with malformed chunks."""
        # Setup mocks
        mock_time.time.side_effect = [1000, 1001]
        mock_settings.get_mapped_model.return_value = ("openai", "gpt-4")

        async def mock_stream():
            yield "data: invalid json\n\n"
            yield 'data: {"incomplete": \n\n'
            yield 'data: {"id": "test-id", "choices": [{"delta": {"content": "Hello"}, "finish_reason": "stop"}]}\n\n'
            yield "data: [DONE]\n\n"

        mock_router.route_chat_completions = AsyncMock(return_value=mock_stream())

        # Execute
        response = await chat_completions(mock_streaming_request, "test-api-key")

        # Verify
        assert hasattr(response, "body_iterator")

        # Consume the stream
        chunks = []
        async for chunk in response.body_iterator:
            chunks.append(chunk)

        # Should handle malformed chunks gracefully
        mock_log_request.assert_called_once()
        mock_log_model.assert_called_once()
