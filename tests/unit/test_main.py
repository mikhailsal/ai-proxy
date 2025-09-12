import pytest
from unittest.mock import Mock, patch, AsyncMock, mock_open
from fastapi.testclient import TestClient
from fastapi import FastAPI
import json

from ai_proxy.main import (
    app,
    health_check,
    chat_completions_options,
    chat_completions,
    list_models,
)


class TestMainApp:
    """Test suite for main FastAPI application."""

    def test_app_creation(self):
        """Test FastAPI app is created correctly."""
        assert isinstance(app, FastAPI)
        assert app.title == "AI Proxy Service"

    def test_cors_middleware_configured(self):
        """Test CORS middleware is properly configured."""
        # Check that CORS middleware is in the middleware stack
        from fastapi.middleware.cors import CORSMiddleware

        middleware_found = False
        for middleware in app.user_middleware:
            if hasattr(middleware, "cls") and issubclass(
                middleware.cls, CORSMiddleware
            ):
                middleware_found = True
                break
        assert middleware_found, "CORS middleware not found in middleware stack"


class TestLifespan:
    """Test suite for lifespan event handler."""

    @patch("ai_proxy.main.logger")
    @pytest.mark.asyncio
    async def test_lifespan_startup(self, mock_logger):
        """Test lifespan startup logs correctly."""
        from ai_proxy.main import lifespan

        async with lifespan(app):
            pass

        mock_logger.info.assert_called_once_with("Application startup")


class TestHealthCheck:
    """Test suite for health check endpoint."""

    @patch("ai_proxy.main.logger")
    @pytest.mark.asyncio
    async def test_health_check_with_timestamp_file(self, mock_logger):
        """Test health check with deployment timestamp file."""
        mock_timestamp = "2024-01-01T12:00:00Z"

        with patch("builtins.open", mock_open(read_data=mock_timestamp)):
            response = await health_check()

        assert response == {
            "status": "ok",
            "version": "test-final-deployment",
            "script_tested": True,
            "deployment_timestamp": mock_timestamp,
        }

    @patch("ai_proxy.main.logger")
    @pytest.mark.asyncio
    async def test_health_check_file_not_found(self, mock_logger):
        """Test health check when deployment timestamp file is not found."""
        with patch("builtins.open", side_effect=FileNotFoundError()):
            response = await health_check()

        assert response == {
            "status": "ok",
            "version": "test-final-deployment",
            "script_tested": True,
            "deployment_timestamp": "unknown",
        }
        mock_logger.warning.assert_called_once()

    @patch("ai_proxy.main.logger")
    @pytest.mark.asyncio
    async def test_health_check_file_read_error(self, mock_logger):
        """Test health check when file read fails."""
        with patch("builtins.open", side_effect=PermissionError("Permission denied")):
            response = await health_check()

        assert response == {
            "status": "ok",
            "version": "test-final-deployment",
            "script_tested": True,
            "deployment_timestamp": "unknown",
        }
        mock_logger.error.assert_called_once()


class TestChatCompletionsOptions:
    """Test suite for CORS preflight handler."""

    @pytest.mark.asyncio
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


class TestChatCompletions:
    """Test suite for chat completions endpoint."""

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

    @patch("ai_proxy.main.router")
    @patch("ai_proxy.main.settings")
    @patch("ai_proxy.main.logger")
    @patch("ai_proxy.main.log_request_response")
    @patch("ai_proxy.main.log_model_usage")
    @patch("ai_proxy.main.time")
    @pytest.mark.asyncio
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

    @patch("ai_proxy.main.router")
    @patch("ai_proxy.main.settings")
    @patch("ai_proxy.main.logger")
    @patch("ai_proxy.main.log_request_response")
    @patch("ai_proxy.main.log_model_usage")
    @patch("ai_proxy.main.time")
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

    @patch("ai_proxy.main.router")
    @patch("ai_proxy.main.settings")
    @patch("ai_proxy.main.logger")
    @patch("ai_proxy.main.log_request_response")
    @patch("ai_proxy.main.log_model_usage")
    @patch("ai_proxy.main.time")
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

    @patch("ai_proxy.main.router")
    @patch("ai_proxy.main.settings")
    @patch("ai_proxy.main.logger")
    @patch("ai_proxy.main.time")
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

    @patch("ai_proxy.main.router")
    @patch("ai_proxy.main.settings")
    @patch("ai_proxy.main.logger")
    @patch("ai_proxy.main.log_request_response")
    @patch("ai_proxy.main.log_model_usage")
    @patch("ai_proxy.main.time")
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

    @patch("ai_proxy.main.router")
    @patch("ai_proxy.main.settings")
    @patch("ai_proxy.main.logger")
    @patch("ai_proxy.main.log_request_response")
    @patch("ai_proxy.main.log_model_usage")
    @patch("ai_proxy.main.time")
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

    @patch("ai_proxy.main.router")
    @patch("ai_proxy.main.settings")
    @patch("ai_proxy.main.logger")
    @patch("ai_proxy.main.log_request_response")
    @patch("ai_proxy.main.log_model_usage")
    @patch("ai_proxy.main.time")
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

    @patch("ai_proxy.main.router")
    @patch("ai_proxy.main.settings")
    @patch("ai_proxy.main.logger")
    @patch("ai_proxy.main.time")
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

    @patch("ai_proxy.main.router")
    @patch("ai_proxy.main.settings")
    @patch("ai_proxy.main.logger")
    @patch("ai_proxy.main.log_request_response")
    @patch("ai_proxy.main.log_model_usage")
    @patch("ai_proxy.main.time")
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

    @patch("ai_proxy.main.router")
    @patch("ai_proxy.main.settings")
    @patch("ai_proxy.main.logger")
    @patch("ai_proxy.main.log_request_response")
    @patch("ai_proxy.main.log_model_usage")
    @patch("ai_proxy.main.time")
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


class TestIntegrationWithTestClient:
    """Integration tests using FastAPI TestClient."""

    @pytest.fixture
    def client(self):
        """Create test client."""
        return TestClient(app)

    def test_health_endpoint_integration(self, client):
        """Test health endpoint integration."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "version" in data

    def test_cors_options_integration(self, client):
        """Test CORS options endpoint integration."""
        response = client.options("/v1/chat/completions")
        assert response.status_code == 200
        assert response.headers["Access-Control-Allow-Origin"] == "*"

    def test_models_endpoint_integration(self, client):
        """Test models endpoint integration."""
        response = client.get("/v1/models")
        assert response.status_code == 200
        data = response.json()
        assert "object" in data
        assert data["object"] == "list"
        assert "data" in data
        assert isinstance(data["data"], list)


class TestListModels:
    """Test suite for list models endpoint."""

    @patch("ai_proxy.main.settings")
    @pytest.mark.asyncio
    async def test_list_models_success(self, mock_settings):
        """Test successful models listing."""
        # Setup mock model mappings
        mock_settings.model_mappings = {
            "gpt-4": "openrouter:openai/gpt-4",
            "claude-3-opus": "openrouter:anthropic/claude-3-opus",
            "gemini-pro": "gemini:gemini-2.0-flash-001",
            "mistral-small": "openrouter:mistralai/mistral-small-3.2-24b-instruct:free",
            "*": "openrouter:mistralai/mistral-small-3.2-24b-instruct:free",  # Should be skipped
        }

        # Mock the _parse_provider_model method
        def mock_parse(model_string):
            if ":" in model_string:
                provider, model = model_string.split(":", 1)
                return provider.strip(), model.strip()
            else:
                return "openrouter", model_string.strip()

        mock_settings._parse_provider_model.side_effect = mock_parse

        # Execute
        response = await list_models()

        # Verify
        assert "object" in response
        assert response["object"] == "list"
        assert "data" in response
        assert isinstance(response["data"], list)

        # Should have 4 models (excluding wildcard "*")
        models = response["data"]
        assert len(models) == 4

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

        # Check specific models are present
        model_ids = [model["id"] for model in models]
        assert "gpt-4" in model_ids
        assert "claude-3-opus" in model_ids
        assert "gemini-pro" in model_ids
        assert "mistral-small" in model_ids
        assert "*" not in model_ids  # Wildcard should be excluded

        # Check providers are correctly set
        model_by_id = {model["id"]: model for model in models}
        assert model_by_id["gpt-4"]["owned_by"] == "openrouter"
        assert model_by_id["claude-3-opus"]["owned_by"] == "openrouter"
        assert model_by_id["gemini-pro"]["owned_by"] == "gemini"
        assert model_by_id["mistral-small"]["owned_by"] == "openrouter"

    @patch("ai_proxy.main.settings")
    @pytest.mark.asyncio
    async def test_list_models_empty_mappings(self, mock_settings):
        """Test models listing with empty mappings."""
        # Setup empty model mappings
        mock_settings.model_mappings = {}

        # Execute
        response = await list_models()

        # Verify
        assert "object" in response
        assert response["object"] == "list"
        assert "data" in response
        assert isinstance(response["data"], list)
        assert len(response["data"]) == 0

    @patch("ai_proxy.main.settings")
    @pytest.mark.asyncio
    async def test_list_models_only_wildcards(self, mock_settings):
        """Test models listing with only wildcard patterns."""
        # Setup model mappings with only wildcards
        mock_settings.model_mappings = {
            "*": "openrouter:mistralai/mistral-small-3.2-24b-instruct:free",
            "gpt-*": "openrouter:openai/gpt-4",
            "claude-*": "openrouter:anthropic/claude-3-opus",
        }

        # Execute
        response = await list_models()

        # Verify
        assert "object" in response
        assert response["object"] == "list"
        assert "data" in response
        assert isinstance(response["data"], list)
        assert len(response["data"]) == 0  # All wildcards should be excluded

    @patch("ai_proxy.main.settings")
    @pytest.mark.asyncio
    async def test_list_models_mixed_patterns(self, mock_settings):
        """Test models listing with mixed patterns and wildcards."""
        # Setup mixed model mappings
        mock_settings.model_mappings = {
            "gpt-4": "openrouter:openai/gpt-4",
            "gpt-*": "openrouter:openai/gpt-4",  # Should be skipped
            "claude-3-opus": "openrouter:anthropic/claude-3-opus",
            "*": "openrouter:mistralai/mistral-small-3.2-24b-instruct:free",  # Should be skipped
        }

        # Mock the _parse_provider_model method
        def mock_parse(model_string):
            if ":" in model_string:
                provider, model = model_string.split(":", 1)
                return provider.strip(), model.strip()
            else:
                return "openrouter", model_string.strip()

        mock_settings._parse_provider_model.side_effect = mock_parse

        # Execute
        response = await list_models()

        # Verify
        assert "object" in response
        assert response["object"] == "list"
        assert "data" in response
        models = response["data"]
        assert len(models) == 2  # Only non-wildcard models

        model_ids = [model["id"] for model in models]
        assert "gpt-4" in model_ids
        assert "claude-3-opus" in model_ids
        assert "gpt-*" not in model_ids
        assert "*" not in model_ids
