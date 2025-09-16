import json
from unittest.mock import patch, MagicMock

from ai_proxy.logging.config import (
    PrettyJSONRenderer,
    get_endpoint_logger,
    get_model_logger,
    log_request_response,
    log_model_usage,
)


class TestPrettyJSONRenderer:
    """Test cases for PrettyJSONRenderer class."""

    def test_pretty_json_renderer_call(self):
        """Test PrettyJSONRenderer formats JSON correctly."""
        renderer = PrettyJSONRenderer()

        event_dict = {
            "level": "info",
            "message": "Test message",
            "timestamp": "2023-01-01T00:00:00Z",
            "data": {"key": "value"},
        }

        result = renderer(None, None, event_dict)

        # Should return formatted JSON string
        assert isinstance(result, str)
        # Should be valid JSON
        parsed = json.loads(result)
        assert parsed == event_dict
        # Should be pretty formatted (contains newlines)
        assert "\n" in result

    def test_pretty_json_renderer_with_non_serializable(self):
        """Test PrettyJSONRenderer handles non-serializable objects."""
        renderer = PrettyJSONRenderer()

        # Create a non-serializable object
        class NonSerializable:
            def __str__(self):
                return "non-serializable-object"

        event_dict = {"message": "Test", "obj": NonSerializable()}

        result = renderer(None, None, event_dict)

        # Should handle non-serializable objects with default=str
        assert isinstance(result, str)
        parsed = json.loads(result)
        assert parsed["obj"] == "non-serializable-object"


class TestGetEndpointLogger:
    """Test cases for get_endpoint_logger function."""

    def test_get_endpoint_logger_creation(self):
        """Test get_endpoint_logger creates logger correctly."""
        with patch("ai_proxy.logging.config.logging.getLogger") as mock_get_logger:
            mock_logger = MagicMock()
            mock_logger.handlers = []
            mock_get_logger.return_value = mock_logger

            with patch(
                "ai_proxy.logging.config.endpoint_handler.get_handler"
            ) as mock_get_handler:
                mock_handler = MagicMock()
                mock_get_handler.return_value = mock_handler

                with patch(
                    "ai_proxy.logging.config.structlog.wrap_logger"
                ) as mock_wrap:
                    mock_wrapped = MagicMock()
                    mock_wrap.return_value = mock_wrapped

                    result = get_endpoint_logger("/v1/chat/completions")

                    # Should get logger with correct name
                    mock_get_logger.assert_called_once_with(
                        "endpoint.v1.chat.completions"
                    )

                    # Should add handler and configure logger
                    mock_logger.addHandler.assert_called_once_with(mock_handler)
                    mock_logger.setLevel.assert_called_once_with(20)  # logging.INFO
                    assert mock_logger.propagate is False

                    # Should wrap with structlog
                    mock_wrap.assert_called_once_with(mock_logger)
                    assert result == mock_wrapped

    def test_get_endpoint_logger_reuse_existing(self):
        """Test get_endpoint_logger reuses existing logger with handlers."""
        with patch("ai_proxy.logging.config.logging.getLogger") as mock_get_logger:
            mock_logger = MagicMock()
            mock_logger.handlers = [MagicMock()]  # Already has handlers
            mock_get_logger.return_value = mock_logger

            with patch("ai_proxy.logging.config.structlog.wrap_logger") as mock_wrap:
                mock_wrapped = MagicMock()
                mock_wrap.return_value = mock_wrapped

                result = get_endpoint_logger("/v1/chat/completions")

                # Should not add handler again
                mock_logger.addHandler.assert_not_called()

                # Should still wrap with structlog
                mock_wrap.assert_called_once_with(mock_logger)
                assert result == mock_wrapped


class TestGetModelLogger:
    """Test cases for get_model_logger function."""

    def test_get_model_logger_creation(self):
        """Test get_model_logger creates logger correctly."""
        with patch("ai_proxy.logging.config.logging.getLogger") as mock_get_logger:
            mock_logger = MagicMock()
            mock_logger.handlers = []
            mock_get_logger.return_value = mock_logger

            with patch(
                "ai_proxy.logging.config.model_handler.get_handler"
            ) as mock_get_handler:
                mock_handler = MagicMock()
                mock_get_handler.return_value = mock_handler

                with patch(
                    "ai_proxy.logging.config.structlog.wrap_logger"
                ) as mock_wrap:
                    mock_wrapped = MagicMock()
                    mock_wrap.return_value = mock_wrapped

                    result = get_model_logger("openai/gpt-4")

                    # Should get logger with correct name
                    mock_get_logger.assert_called_once_with("model.openai.gpt-4")

                    # Should add handler and configure logger
                    mock_logger.addHandler.assert_called_once_with(mock_handler)
                    mock_logger.setLevel.assert_called_once_with(20)  # logging.INFO
                    assert mock_logger.propagate is False

                    # Should wrap with structlog
                    mock_wrap.assert_called_once_with(mock_logger)
                    assert result == mock_wrapped

    def test_get_model_logger_name_cleaning(self):
        """Test get_model_logger cleans model names for logger names."""
        with patch("ai_proxy.logging.config.logging.getLogger") as mock_get_logger:
            mock_logger = MagicMock()
            mock_logger.handlers = []
            mock_get_logger.return_value = mock_logger

            with patch("ai_proxy.logging.config.model_handler.get_handler"):
                with patch("ai_proxy.logging.config.structlog.wrap_logger"):
                    get_model_logger("anthropic:claude-3-opus")

                    # Should clean colons to dots
                    mock_get_logger.assert_called_once_with(
                        "model.anthropic.claude-3-opus"
                    )


class TestLogRequestResponse:
    """Test cases for log_request_response function."""

    @patch("ai_proxy.logging.config.get_endpoint_logger")
    @patch("ai_proxy.logging.config.datetime")
    def test_log_request_response(self, mock_datetime, mock_get_endpoint_logger):
        """Test log_request_response logs correctly."""
        mock_datetime.utcnow.return_value.isoformat.return_value = (
            "2023-01-01T00:00:00Z"
        )

        mock_logger = MagicMock()
        mock_get_endpoint_logger.return_value = mock_logger

        request_data = {"model": "gpt-4", "messages": []}
        response_data = {"id": "test", "choices": []}

        log_request_response(
            endpoint="/v1/chat/completions",
            request_data=request_data,
            response_data=response_data,
            status_code=200,
            latency_ms=123.456,
            api_key_hash="hash123",
        )

        # Should get endpoint logger
        mock_get_endpoint_logger.assert_called_once_with("/v1/chat/completions")

        # Should log with correct data
        mock_logger.info.assert_called_once()
        args, kwargs = mock_logger.info.call_args
        assert args[0] == "API Request/Response"
        assert kwargs["endpoint"] == "/v1/chat/completions"
        assert kwargs["status_code"] == 200
        assert kwargs["latency_ms"] == 123.46  # Rounded
        assert kwargs["request"] == request_data
        assert kwargs["response"] == response_data
        assert kwargs["api_key_hash"] == "hash123"

    @patch("ai_proxy.logging.config.get_endpoint_logger")
    @patch("ai_proxy.logging.config.datetime")
    def test_log_request_response_without_api_key(
        self, mock_datetime, mock_get_endpoint_logger
    ):
        """Test log_request_response without API key hash."""
        mock_datetime.utcnow.return_value.isoformat.return_value = (
            "2023-01-01T00:00:00Z"
        )

        mock_logger = MagicMock()
        mock_get_endpoint_logger.return_value = mock_logger

        log_request_response(
            endpoint="/v1/chat/completions",
            request_data={},
            response_data={},
            status_code=200,
            latency_ms=100.0,
        )

        # Should log without api_key_hash
        mock_logger.info.assert_called_once()
        args, kwargs = mock_logger.info.call_args
        assert "api_key_hash" not in kwargs


class TestLogModelUsage:
    """Test cases for log_model_usage function."""

    @patch("ai_proxy.logging.config.get_model_logger")
    @patch("ai_proxy.logging.config.datetime")
    def test_log_model_usage_different_models(
        self, mock_datetime, mock_get_model_logger
    ):
        """Test log_model_usage with different original and mapped models."""
        mock_datetime.utcnow.return_value.isoformat.return_value = (
            "2023-01-01T00:00:00Z"
        )

        mock_original_logger = MagicMock()
        mock_mapped_logger = MagicMock()

        def mock_get_logger(model_name):
            if model_name == "gpt-4":
                return mock_original_logger
            elif model_name == "openai/gpt-4":
                return mock_mapped_logger
            return MagicMock()

        mock_get_model_logger.side_effect = mock_get_logger

        log_model_usage(
            original_model="gpt-4",
            mapped_model="openai/gpt-4",
            request_data={"messages": []},
            response_data={"choices": []},
            status_code=200,
            latency_ms=150.0,
            api_key_hash="hash123",
        )

        # Should get loggers for both models
        assert mock_get_model_logger.call_count == 2

        # Should log to both loggers
        mock_original_logger.info.assert_called_once()
        mock_mapped_logger.info.assert_called_once()

        # Check original logger call
        args, kwargs = mock_original_logger.info.call_args
        assert args[0] == "Model usage (original)"
        assert kwargs["original_model"] == "gpt-4"
        assert kwargs["mapped_model"] == "openai/gpt-4"

        # Check mapped logger call
        args, kwargs = mock_mapped_logger.info.call_args
        assert args[0] == "Model usage (mapped)"
        assert kwargs["original_model"] == "gpt-4"
        assert kwargs["mapped_model"] == "openai/gpt-4"

    @patch("ai_proxy.logging.config.get_model_logger")
    @patch("ai_proxy.logging.config.datetime")
    def test_log_model_usage_same_models(self, mock_datetime, mock_get_model_logger):
        """Test log_model_usage with same original and mapped models."""
        mock_datetime.utcnow.return_value.isoformat.return_value = (
            "2023-01-01T00:00:00Z"
        )

        mock_logger = MagicMock()
        mock_get_model_logger.return_value = mock_logger

        log_model_usage(
            original_model="gpt-4",
            mapped_model="gpt-4",
            request_data={"messages": []},
            response_data={"choices": []},
            status_code=200,
            latency_ms=150.0,
        )

        # Should get logger only once (for original model)
        mock_get_model_logger.assert_called_once_with("gpt-4")

        # Should log only once
        mock_logger.info.assert_called_once()

    @patch("ai_proxy.logging.config.get_model_logger")
    @patch("ai_proxy.logging.config.datetime")
    def test_log_model_usage_no_original_model(
        self, mock_datetime, mock_get_model_logger
    ):
        """Test log_model_usage with no original model."""
        mock_datetime.utcnow.return_value.isoformat.return_value = (
            "2023-01-01T00:00:00Z"
        )

        mock_logger = MagicMock()
        mock_get_model_logger.return_value = mock_logger

        log_model_usage(
            original_model=None,
            mapped_model="gpt-4",
            request_data={"messages": []},
            response_data={"choices": []},
            status_code=200,
            latency_ms=150.0,
        )

        # Should get logger only for mapped model
        mock_get_model_logger.assert_called_once_with("gpt-4")

        # Should log only once
        mock_logger.info.assert_called_once()
