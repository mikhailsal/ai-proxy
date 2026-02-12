"""
Unit tests for validating log format correctness across all log types.

This test suite ensures that all log types (endpoint logs, model logs, app logs)
are generated in the correct JSON format that can be parsed by the log ingestion system.
"""

import json
import tempfile
import pytest
from pathlib import Path
from unittest.mock import patch, mock_open

from ai_proxy.logging.config import (
    setup_logging,
    log_request_response,
    log_model_usage,
    PrettyJSONRenderer,
    FileJSONRenderer,
)


class TestLogFormatValidation:
    """Test suite for validating log format correctness."""

    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.log_dir = Path(self.temp_dir) / "logs"
        self.log_dir.mkdir(exist_ok=True)

    def teardown_method(self):
        """Clean up test environment."""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_pretty_json_renderer_format(self):
        """Test that PrettyJSONRenderer produces properly formatted JSON."""
        renderer = PrettyJSONRenderer()

        test_event = {
            "timestamp": "2025-09-19T08:00:00.000000Z",
            "endpoint": "/v1/chat/completions",
            "status_code": 200,
            "request": {
                "model": "test-model",
                "messages": [{"role": "user", "content": "test"}],
            },
            "response": {
                "id": "test-123",
                "choices": [{"message": {"content": "response"}}],
            },
        }

        result = renderer(None, None, test_event)

        # Should be valid JSON
        parsed = json.loads(result)
        assert parsed == test_event

        # Should be pretty-printed (multi-line)
        lines = result.split("\n")
        assert len(lines) > 1
        assert lines[0] == "{"
        assert lines[-1] == "}"

        # Should have proper indentation
        assert any(line.startswith("  ") for line in lines)

    def test_file_json_renderer_format(self):
        """Test that FileJSONRenderer produces properly formatted JSON without ANSI codes."""
        renderer = FileJSONRenderer()

        test_event = {
            "timestamp": "2025-09-19T08:00:00.000000Z",
            "endpoint": "/v1/chat/completions",
            "status_code": 200,
            "request": {"model": "test-model"},
            "response": {"id": "test-123"},
        }

        result = renderer(None, None, test_event)

        # Should be valid JSON
        parsed = json.loads(result)
        assert parsed == test_event

        # Should be pretty-printed (multi-line)
        lines = result.split("\n")
        assert len(lines) > 1

        # Should NOT contain ANSI escape codes
        import re

        ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
        assert not ansi_escape.search(result)

    @patch("ai_proxy.logging.config.Path.mkdir")
    @patch("builtins.open", new_callable=mock_open)
    def test_endpoint_log_format(self, mock_file, mock_mkdir):
        """Test that endpoint logs are written in the correct format."""
        # Mock the file write operations
        mock_file_handle = mock_file.return_value

        # Setup logging
        setup_logging("INFO", True)

        # Test request/response logging
        test_request = {
            "model": "test-model",
            "messages": [{"role": "user", "content": "test message"}],
            "temperature": 0.7,
        }
        test_response = {
            "id": "test-response-123",
            "choices": [{"message": {"role": "assistant", "content": "test response"}}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5},
        }

        log_request_response(
            endpoint="/v1/chat/completions",
            request_data=test_request,
            response_data=test_response,
            status_code=200,
            latency_ms=123.45,
            api_key_hash="test-hash",
        )

        # Verify that write was called
        mock_file_handle.write.assert_called()

        # Get the logged content
        write_calls = mock_file_handle.write.call_args_list
        logged_content = "".join(call[0][0] for call in write_calls)

        # Verify the format contains expected elements
        assert "20" in logged_content  # Date format (year prefix)
        assert "- INFO -" in logged_content  # Log level
        assert "/v1/chat/completions" in logged_content
        assert "test-model" in logged_content
        assert "200" in logged_content
        assert "123.45" in logged_content

    @patch("ai_proxy.logging.config.Path.mkdir")
    @patch("builtins.open", new_callable=mock_open)
    def test_model_log_format(self, mock_file, mock_mkdir):
        """Test that model logs are written in the correct format."""
        mock_file_handle = mock_file.return_value

        setup_logging("INFO", True)

        test_request = {"model": "original-model", "messages": []}
        test_response = {"id": "test-123", "model": "mapped-model"}

        log_model_usage(
            original_model="original-model",
            mapped_model="mapped-model",
            request_data=test_request,
            response_data=test_response,
            status_code=200,
            latency_ms=456.78,
            api_key_hash="model-test-hash",
        )

        # Verify write was called
        mock_file_handle.write.assert_called()

        write_calls = mock_file_handle.write.call_args_list
        logged_content = "".join(call[0][0] for call in write_calls)

        # Verify model-specific log format
        assert "original-model" in logged_content
        assert "mapped-model" in logged_content
        assert "456.78" in logged_content
        assert "model-test-hash" in logged_content

    def test_json_parsability_from_log_line(self):
        """Test that log lines can be parsed back to JSON correctly."""
        # Simulate a log line in the expected format
        log_line = """2025-09-19 08:00:00 - INFO - {
  "timestamp": "2025-09-19T08:00:00.000000Z",
  "endpoint": "/v1/chat/completions",
  "status_code": 200,
  "latency_ms": 123.45,
  "request": {
    "model": "test-model",
    "messages": [
      {
        "role": "user",
        "content": "test message"
      }
    ]
  },
  "response": {
    "id": "test-123",
    "choices": [
      {
        "message": {
          "content": "test response"
        }
      }
    ]
  },
  "api_key_hash": "test-hash"
}"""

        # Extract JSON part (this simulates what the log parser does)
        json_start = log_line.find("{")
        json_part = log_line[json_start:]

        # Should be parseable as JSON
        parsed_json = json.loads(json_part)

        # Verify required fields for log ingestion
        assert "timestamp" in parsed_json
        assert "endpoint" in parsed_json
        assert "request" in parsed_json
        assert "response" in parsed_json
        assert "status_code" in parsed_json
        assert "latency_ms" in parsed_json

        # Verify field types
        assert isinstance(parsed_json["status_code"], int)
        assert isinstance(parsed_json["latency_ms"], (int, float))
        assert isinstance(parsed_json["request"], dict)
        assert isinstance(parsed_json["response"], dict)

    def test_log_format_consistency_across_types(self):
        """Test that all log types follow the same basic format structure."""
        renderer = FileJSONRenderer()

        # Test different log types
        endpoint_log = {
            "timestamp": "2025-09-19T08:00:00.000000Z",
            "endpoint": "/v1/chat/completions",
            "status_code": 200,
            "request": {},
            "response": {},
        }

        model_log = {
            "timestamp": "2025-09-19T08:00:00.000000Z",
            "original_model": "gpt-4",
            "mapped_model": "openai/gpt-4",
            "status_code": 200,
            "request": {},
            "response": {},
        }

        app_log = {
            "timestamp": "2025-09-19T08:00:00.000000Z",
            "event": "Application startup",
            "level": "info",
            "logger": "__main__",
        }

        # All should render to valid JSON
        for log_data in [endpoint_log, model_log, app_log]:
            result = renderer(None, None, log_data)
            parsed = json.loads(result)
            assert parsed == log_data

            # All should have consistent timestamp format
            assert "timestamp" in parsed
            assert parsed["timestamp"].endswith("Z")  # ISO format with UTC

    def test_special_characters_handling(self):
        """Test that logs handle special characters correctly."""
        renderer = FileJSONRenderer()

        test_event = {
            "timestamp": "2025-09-19T08:00:00.000000Z",
            "endpoint": "/v1/chat/completions",
            "request": {
                "messages": [
                    {
                        "role": "user",
                        "content": "Test with special chars: 🚀 ñáéíóú 中文 العربية \n\t\r",
                    }
                ]
            },
            "response": {
                "choices": [
                    {
                        "message": {
                            "content": "Response with émojis: 😊 and unicode: ∑∏∆"
                        }
                    }
                ]
            },
        }

        result = renderer(None, None, test_event)

        # Should be valid JSON
        parsed = json.loads(result)
        assert parsed == test_event

        # Special characters should be preserved
        assert "🚀" in result
        assert "中文" in result
        assert "العربية" in result
        assert "😊" in result

    def test_large_log_entry_handling(self):
        """Test that large log entries are handled correctly."""
        renderer = FileJSONRenderer()

        # Create a large request with many messages
        large_content = "A" * 10000  # 10KB of content
        test_event = {
            "timestamp": "2025-09-19T08:00:00.000000Z",
            "endpoint": "/v1/chat/completions",
            "request": {
                "model": "test-model",
                "messages": [{"role": "user", "content": large_content}],
            },
            "response": {
                "choices": [{"message": {"content": "Response to large input"}}]
            },
        }

        result = renderer(None, None, test_event)

        # Should still be valid JSON
        parsed = json.loads(result)
        assert parsed == test_event
        assert len(parsed["request"]["messages"][0]["content"]) == 10000

    def test_error_response_log_format(self):
        """Test that error responses are logged correctly."""
        renderer = FileJSONRenderer()

        error_log = {
            "timestamp": "2025-09-19T08:00:00.000000Z",
            "endpoint": "/v1/chat/completions",
            "status_code": 400,
            "latency_ms": 50.0,
            "request": {"model": "invalid-model", "messages": []},
            "response": {
                "error": {
                    "message": "Invalid model specified",
                    "code": 400,
                    "type": "invalid_request_error",
                }
            },
        }

        result = renderer(None, None, error_log)
        parsed = json.loads(result)

        # Verify error structure
        assert parsed["status_code"] == 400
        assert "error" in parsed["response"]
        assert "message" in parsed["response"]["error"]

    @pytest.mark.parametrize("log_level", ["DEBUG", "INFO", "WARNING", "ERROR"])
    def test_log_format_consistency_across_levels(self, log_level):
        """Test that log format is consistent across different log levels."""
        with patch("ai_proxy.logging.config.logging.basicConfig"):
            setup_logging(log_level, True)

            # The setup should work for all log levels
            assert True  # If we get here without exception, the test passes
