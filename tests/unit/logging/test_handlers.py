import logging
import tempfile
from pathlib import Path

from ai_proxy.logging.config import (
    EndpointFileHandler,
    ModelFileHandler,
)


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
            assert (
                "multiple___slashes" in handler.handlers
            )  # Multiple slashes become underscores
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
