import pytest
import logging
import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock, mock_open
from datetime import datetime
import structlog

from ai_proxy.logging.config import (
    PrettyJSONRenderer,
    EndpointFileHandler,
    ModelFileHandler,
    setup_logging,
    get_endpoint_logger,
    get_model_logger,
    log_request_response,
    log_model_usage,
    logger,
    endpoint_handler,
    model_handler
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
            "data": {"key": "value"}
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
        
        event_dict = {
            "message": "Test",
            "obj": NonSerializable()
        }
        
        result = renderer(None, None, event_dict)
        
        # Should handle non-serializable objects with default=str
        assert isinstance(result, str)
        parsed = json.loads(result)
        assert parsed["obj"] == "non-serializable-object"


class TestEndpointFileHandler:
    """Test cases for EndpointFileHandler class."""

    def test_endpoint_file_handler_init(self):
        """Test EndpointFileHandler initialization."""
        with tempfile.TemporaryDirectory() as tmpdir:
            handler = EndpointFileHandler(base_log_dir=tmpdir)
            
            assert handler.base_log_dir == Path(tmpdir)
            assert isinstance(handler.handlers, dict)
            assert len(handler.handlers) == 0

    def test_endpoint_file_handler_get_handler(self):
        """Test EndpointFileHandler get_handler method."""
        with tempfile.TemporaryDirectory() as tmpdir:
            handler = EndpointFileHandler(base_log_dir=tmpdir)
            
            file_handler = handler.get_handler("test_endpoint")
            
            assert isinstance(file_handler, logging.FileHandler)
            assert "test_endpoint" in handler.handlers
            assert handler.handlers["test_endpoint"] == file_handler

    def test_endpoint_file_handler_clean_endpoint_name(self):
        """Test EndpointFileHandler cleans endpoint names for filenames."""
        with tempfile.TemporaryDirectory() as tmpdir:
            handler = EndpointFileHandler(base_log_dir=tmpdir)
            
            # Test various endpoint names
            handler.get_handler("/v1/chat/completions")
            handler.get_handler("api:endpoint")
            handler.get_handler("///multiple///slashes///")
            handler.get_handler("")
            
            # Should have cleaned names
            assert "v1_chat_completions" in handler.handlers
            assert "apiendpoint" in handler.handlers
            assert "multiple___slashes" in handler.handlers  # Multiple slashes become underscores
            assert "general" in handler.handlers

    def test_endpoint_file_handler_reuse_handler(self):
        """Test EndpointFileHandler reuses existing handlers."""
        with tempfile.TemporaryDirectory() as tmpdir:
            handler = EndpointFileHandler(base_log_dir=tmpdir)
            
            handler1 = handler.get_handler("test_endpoint")
            handler2 = handler.get_handler("test_endpoint")
            
            # Should be the same handler instance
            assert handler1 is handler2
            assert len(handler.handlers) == 1


class TestModelFileHandler:
    """Test cases for ModelFileHandler class."""

    def test_model_file_handler_init(self):
        """Test ModelFileHandler initialization."""
        with tempfile.TemporaryDirectory() as tmpdir:
            handler = ModelFileHandler(base_log_dir=tmpdir)
            
            assert handler.base_log_dir == Path(tmpdir)
            assert isinstance(handler.handlers, dict)
            assert len(handler.handlers) == 0

    def test_model_file_handler_get_handler(self):
        """Test ModelFileHandler get_handler method."""
        with tempfile.TemporaryDirectory() as tmpdir:
            handler = ModelFileHandler(base_log_dir=tmpdir)
            
            file_handler = handler.get_handler("gpt-4")
            
            assert isinstance(file_handler, logging.FileHandler)
            assert "gpt-4" in handler.handlers
            assert handler.handlers["gpt-4"] == file_handler

    def test_model_file_handler_clean_model_name(self):
        """Test ModelFileHandler cleans model names for filenames."""
        with tempfile.TemporaryDirectory() as tmpdir:
            handler = ModelFileHandler(base_log_dir=tmpdir)
            
            # Test various model names
            handler.get_handler("openai/gpt-4")
            handler.get_handler("anthropic:claude-3-opus")
            handler.get_handler("gpt-4*")
            handler.get_handler("")
            
            # Should have cleaned names
            assert "openai_gpt-4" in handler.handlers
            assert "anthropic_claude-3-opus" in handler.handlers
            assert "gpt-4star" in handler.handlers
            assert "unknown_model" in handler.handlers

    def test_model_file_handler_reuse_handler(self):
        """Test ModelFileHandler reuses existing handlers."""
        with tempfile.TemporaryDirectory() as tmpdir:
            handler = ModelFileHandler(base_log_dir=tmpdir)
            
            handler1 = handler.get_handler("gpt-4")
            handler2 = handler.get_handler("gpt-4")
            
            # Should be the same handler instance
            assert handler1 is handler2
            assert len(handler.handlers) == 1


class TestSetupLogging:
    """Test cases for setup_logging function."""

    @patch('ai_proxy.logging.config.logging.basicConfig')
    @patch('ai_proxy.logging.config.structlog.configure')
    @patch('ai_proxy.logging.config.Path.mkdir')
    def test_setup_logging_with_file_logging(self, mock_mkdir, mock_structlog_configure, mock_basic_config):
        """Test setup_logging with file logging enabled."""
        setup_logging(log_level="DEBUG", enable_file_logging=True)
        
        # Should create logs directory
        mock_mkdir.assert_called_once_with(exist_ok=True)
        
        # Should configure basic logging with file handler
        mock_basic_config.assert_called_once()
        args, kwargs = mock_basic_config.call_args
        assert kwargs['level'] == logging.DEBUG
        assert len(kwargs['handlers']) == 2  # console + file
        
        # Should configure structlog
        mock_structlog_configure.assert_called_once()

    @patch('ai_proxy.logging.config.logging.basicConfig')
    @patch('ai_proxy.logging.config.structlog.configure')
    @patch('ai_proxy.logging.config.Path.mkdir')
    def test_setup_logging_without_file_logging(self, mock_mkdir, mock_structlog_configure, mock_basic_config):
        """Test setup_logging with file logging disabled."""
        setup_logging(log_level="WARNING", enable_file_logging=False)
        
        # Should still create logs directory
        mock_mkdir.assert_called_once_with(exist_ok=True)
        
        # Should configure basic logging with only console handler
        mock_basic_config.assert_called_once()
        args, kwargs = mock_basic_config.call_args
        assert kwargs['level'] == logging.WARNING
        assert len(kwargs['handlers']) == 1  # console only
        
        # Should configure structlog
        mock_structlog_configure.assert_called_once()

    @patch('ai_proxy.logging.config.logging.basicConfig')
    @patch('ai_proxy.logging.config.structlog.configure')
    @patch('ai_proxy.logging.config.Path.mkdir')
    def test_setup_logging_invalid_log_level(self, mock_mkdir, mock_structlog_configure, mock_basic_config):
        """Test setup_logging with invalid log level defaults to INFO."""
        setup_logging(log_level="INVALID", enable_file_logging=True)
        
        # Should default to INFO level
        mock_basic_config.assert_called_once()
        args, kwargs = mock_basic_config.call_args
        assert kwargs['level'] == logging.INFO


class TestGetEndpointLogger:
    """Test cases for get_endpoint_logger function."""

    def test_get_endpoint_logger_creation(self):
        """Test get_endpoint_logger creates logger correctly."""
        with patch('ai_proxy.logging.config.logging.getLogger') as mock_get_logger:
            mock_logger = MagicMock()
            mock_logger.handlers = []
            mock_get_logger.return_value = mock_logger
            
            with patch('ai_proxy.logging.config.endpoint_handler.get_handler') as mock_get_handler:
                mock_handler = MagicMock()
                mock_get_handler.return_value = mock_handler
                
                with patch('ai_proxy.logging.config.structlog.wrap_logger') as mock_wrap:
                    mock_wrapped = MagicMock()
                    mock_wrap.return_value = mock_wrapped
                    
                    result = get_endpoint_logger("/v1/chat/completions")
                    
                    # Should get logger with correct name
                    mock_get_logger.assert_called_once_with("endpoint.v1.chat.completions")
                    
                    # Should add handler and configure logger
                    mock_logger.addHandler.assert_called_once_with(mock_handler)
                    mock_logger.setLevel.assert_called_once_with(logging.INFO)
                    assert mock_logger.propagate is False
                    
                    # Should wrap with structlog
                    mock_wrap.assert_called_once_with(mock_logger)
                    assert result == mock_wrapped

    def test_get_endpoint_logger_reuse_existing(self):
        """Test get_endpoint_logger reuses existing logger with handlers."""
        with patch('ai_proxy.logging.config.logging.getLogger') as mock_get_logger:
            mock_logger = MagicMock()
            mock_logger.handlers = [MagicMock()]  # Already has handlers
            mock_get_logger.return_value = mock_logger
            
            with patch('ai_proxy.logging.config.structlog.wrap_logger') as mock_wrap:
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
        with patch('ai_proxy.logging.config.logging.getLogger') as mock_get_logger:
            mock_logger = MagicMock()
            mock_logger.handlers = []
            mock_get_logger.return_value = mock_logger
            
            with patch('ai_proxy.logging.config.model_handler.get_handler') as mock_get_handler:
                mock_handler = MagicMock()
                mock_get_handler.return_value = mock_handler
                
                with patch('ai_proxy.logging.config.structlog.wrap_logger') as mock_wrap:
                    mock_wrapped = MagicMock()
                    mock_wrap.return_value = mock_wrapped
                    
                    result = get_model_logger("openai/gpt-4")
                    
                    # Should get logger with correct name
                    mock_get_logger.assert_called_once_with("model.openai.gpt-4")
                    
                    # Should add handler and configure logger
                    mock_logger.addHandler.assert_called_once_with(mock_handler)
                    mock_logger.setLevel.assert_called_once_with(logging.INFO)
                    assert mock_logger.propagate is False
                    
                    # Should wrap with structlog
                    mock_wrap.assert_called_once_with(mock_logger)
                    assert result == mock_wrapped

    def test_get_model_logger_name_cleaning(self):
        """Test get_model_logger cleans model names for logger names."""
        with patch('ai_proxy.logging.config.logging.getLogger') as mock_get_logger:
            mock_logger = MagicMock()
            mock_logger.handlers = []
            mock_get_logger.return_value = mock_logger
            
            with patch('ai_proxy.logging.config.model_handler.get_handler'):
                with patch('ai_proxy.logging.config.structlog.wrap_logger'):
                    get_model_logger("anthropic:claude-3-opus")
                    
                    # Should clean colons to dots
                    mock_get_logger.assert_called_once_with("model.anthropic.claude-3-opus")


class TestLogRequestResponse:
    """Test cases for log_request_response function."""

    @patch('ai_proxy.logging.config.get_endpoint_logger')
    @patch('ai_proxy.logging.config.datetime')
    def test_log_request_response(self, mock_datetime, mock_get_endpoint_logger):
        """Test log_request_response logs correctly."""
        mock_datetime.utcnow.return_value.isoformat.return_value = "2023-01-01T00:00:00Z"
        
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
            api_key_hash="hash123"
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

    @patch('ai_proxy.logging.config.get_endpoint_logger')
    @patch('ai_proxy.logging.config.datetime')
    def test_log_request_response_without_api_key(self, mock_datetime, mock_get_endpoint_logger):
        """Test log_request_response without API key hash."""
        mock_datetime.utcnow.return_value.isoformat.return_value = "2023-01-01T00:00:00Z"
        
        mock_logger = MagicMock()
        mock_get_endpoint_logger.return_value = mock_logger
        
        log_request_response(
            endpoint="/v1/chat/completions",
            request_data={},
            response_data={},
            status_code=200,
            latency_ms=100.0
        )
        
        # Should log without api_key_hash
        mock_logger.info.assert_called_once()
        args, kwargs = mock_logger.info.call_args
        assert "api_key_hash" not in kwargs


class TestLogModelUsage:
    """Test cases for log_model_usage function."""

    @patch('ai_proxy.logging.config.get_model_logger')
    @patch('ai_proxy.logging.config.datetime')
    def test_log_model_usage_different_models(self, mock_datetime, mock_get_model_logger):
        """Test log_model_usage with different original and mapped models."""
        mock_datetime.utcnow.return_value.isoformat.return_value = "2023-01-01T00:00:00Z"
        
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
            api_key_hash="hash123"
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

    @patch('ai_proxy.logging.config.get_model_logger')
    @patch('ai_proxy.logging.config.datetime')
    def test_log_model_usage_same_models(self, mock_datetime, mock_get_model_logger):
        """Test log_model_usage with same original and mapped models."""
        mock_datetime.utcnow.return_value.isoformat.return_value = "2023-01-01T00:00:00Z"
        
        mock_logger = MagicMock()
        mock_get_model_logger.return_value = mock_logger
        
        log_model_usage(
            original_model="gpt-4",
            mapped_model="gpt-4",
            request_data={"messages": []},
            response_data={"choices": []},
            status_code=200,
            latency_ms=150.0
        )
        
        # Should get logger only once (for original model)
        mock_get_model_logger.assert_called_once_with("gpt-4")
        
        # Should log only once
        mock_logger.info.assert_called_once()

    @patch('ai_proxy.logging.config.get_model_logger')
    @patch('ai_proxy.logging.config.datetime')
    def test_log_model_usage_no_original_model(self, mock_datetime, mock_get_model_logger):
        """Test log_model_usage with no original model."""
        mock_datetime.utcnow.return_value.isoformat.return_value = "2023-01-01T00:00:00Z"
        
        mock_logger = MagicMock()
        mock_get_model_logger.return_value = mock_logger
        
        log_model_usage(
            original_model=None,
            mapped_model="gpt-4",
            request_data={"messages": []},
            response_data={"choices": []},
            status_code=200,
            latency_ms=150.0
        )
        
        # Should get logger only for mapped model
        mock_get_model_logger.assert_called_once_with("gpt-4")
        
        # Should log only once
        mock_logger.info.assert_called_once()


class TestGlobalInstances:
    """Test cases for global instances."""

    def test_logger_instance(self):
        """Test that logger is a structlog instance."""
        assert logger is not None
        # Should be a structlog logger
        assert hasattr(logger, 'info')
        assert hasattr(logger, 'error')
        assert hasattr(logger, 'bind')

    def test_endpoint_handler_instance(self):
        """Test that endpoint_handler is an EndpointFileHandler instance."""
        assert isinstance(endpoint_handler, EndpointFileHandler)
        assert hasattr(endpoint_handler, 'get_handler')
        assert hasattr(endpoint_handler, 'handlers')

    def test_model_handler_instance(self):
        """Test that model_handler is a ModelFileHandler instance."""
        assert isinstance(model_handler, ModelFileHandler)
        assert hasattr(model_handler, 'get_handler')
        assert hasattr(model_handler, 'handlers') 