import logging
from unittest.mock import patch

from ai_proxy.logging.config import (
    setup_logging,
    logger,
    endpoint_handler,
    model_handler,
    EndpointFileHandler,
    ModelFileHandler,
)


class TestSetupLogging:
    """Test cases for setup_logging function."""

    @patch("ai_proxy.logging.config.logging.basicConfig")
    @patch("ai_proxy.logging.config.structlog.configure")
    @patch("ai_proxy.logging.config.Path.mkdir")
    def test_setup_logging_with_file_logging(
        self, mock_mkdir, mock_structlog_configure, mock_basic_config
    ):
        """Test setup_logging with file logging enabled."""
        setup_logging(log_level="DEBUG", enable_file_logging=True)

        # Should create logs directory
        mock_mkdir.assert_called_once_with(exist_ok=True)

        # Should configure basic logging with file handler
        mock_basic_config.assert_called_once()
        args, kwargs = mock_basic_config.call_args
        assert kwargs["level"] == logging.DEBUG
        assert len(kwargs["handlers"]) == 2  # console + file

        # Should configure structlog
        mock_structlog_configure.assert_called_once()

    @patch("ai_proxy.logging.config.logging.basicConfig")
    @patch("ai_proxy.logging.config.structlog.configure")
    @patch("ai_proxy.logging.config.Path.mkdir")
    def test_setup_logging_without_file_logging(
        self, mock_mkdir, mock_structlog_configure, mock_basic_config
    ):
        """Test setup_logging with file logging disabled."""
        setup_logging(log_level="WARNING", enable_file_logging=False)

        # Should still create logs directory
        mock_mkdir.assert_called_once_with(exist_ok=True)

        # Should configure basic logging with only console handler
        mock_basic_config.assert_called_once()
        args, kwargs = mock_basic_config.call_args
        assert kwargs["level"] == logging.WARNING
        assert len(kwargs["handlers"]) == 1  # console only

        # Should configure structlog
        mock_structlog_configure.assert_called_once()

    @patch("ai_proxy.logging.config.logging.basicConfig")
    @patch("ai_proxy.logging.config.structlog.configure")
    @patch("ai_proxy.logging.config.Path.mkdir")
    def test_setup_logging_invalid_log_level(
        self, mock_mkdir, mock_structlog_configure, mock_basic_config
    ):
        """Test setup_logging with invalid log level defaults to INFO."""
        setup_logging(log_level="INVALID", enable_file_logging=True)

        # Should default to INFO level
        mock_basic_config.assert_called_once()
        args, kwargs = mock_basic_config.call_args
        assert kwargs["level"] == logging.INFO


class TestGlobalInstances:
    """Test cases for global instances."""

    def test_logger_instance(self):
        """Test that logger is a structlog instance."""
        assert logger is not None
        # Should be a structlog logger
        assert hasattr(logger, "info")
        assert hasattr(logger, "error")
        assert hasattr(logger, "bind")

    def test_endpoint_handler_instance(self):
        """Test that endpoint_handler is an EndpointFileHandler instance."""
        assert isinstance(endpoint_handler, EndpointFileHandler)
        assert hasattr(endpoint_handler, "get_handler")
        assert hasattr(endpoint_handler, "handlers")

    def test_model_handler_instance(self):
        """Test that model_handler is a ModelFileHandler instance."""
        assert isinstance(model_handler, ModelFileHandler)
        assert hasattr(model_handler, "get_handler")
        assert hasattr(model_handler, "handlers")
