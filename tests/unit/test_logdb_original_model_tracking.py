"""
Unit tests for original model tracking in log parser.

Tests that the log parser correctly extracts the original model requested by the user
(before routing) and the mapped model (after routing).
"""

import json

from ai_proxy.logdb.parsers.log_parser import _normalize_entry


class TestOriginalModelTracking:
    """Test that original model is preserved through routing and logging."""

    def test_original_model_preserved_with_direct_mapping(self):
        """
        Test that when a model is mapped (e.g., mistral-small -> mistralai/mistral-small...),
        the original model is preserved in _original_model field and extracted correctly.
        """
        # Simulate log entry as it would be written with routing
        log_entry = {
            "timestamp": "2025-10-09T12:00:00.000Z",
            "endpoint": "/v1/chat/completions",
            "status_code": 200,
            "latency_ms": 1500.50,
            "request": {
                "_original_model": "mistral-small",
                "model": "mistralai/mistral-small-3.2-24b-instruct:free",
                "messages": [{"role": "user", "content": "Hello"}],
                "stream": False,
            },
            "response": {
                "id": "gen-123",
                "model": "mistralai/mistral-small-3.2-24b-instruct:free",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "Hi!"},
                    }
                ],
            },
        }

        normalized = _normalize_entry(log_entry)

        assert normalized is not None
        assert normalized["model_original"] == "mistral-small"
        assert (
            normalized["model_mapped"]
            == "mistralai/mistral-small-3.2-24b-instruct:free"
        )
        assert normalized["endpoint"] == "/v1/chat/completions"
        assert normalized["status_code"] == 200

    def test_original_model_preserved_with_wildcard_routing(self):
        """
        Test that when a model uses wildcard routing (unrecognized model -> deepseek),
        the original model is still preserved.
        """
        log_entry = {
            "timestamp": "2025-10-09T12:00:00.000Z",
            "endpoint": "/v1/chat/completions",
            "status_code": 200,
            "latency_ms": 1450.33,
            "request": {
                "_original_model": "some-unknown-model",
                "model": "deepseek/deepseek-chat-v3.1:free",
                "messages": [{"role": "user", "content": "Test"}],
                "stream": False,
            },
            "response": {
                "id": "gen-456",
                "model": "deepseek/deepseek-chat-v3.1:free",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "Response"},
                    }
                ],
            },
        }

        normalized = _normalize_entry(log_entry)

        assert normalized is not None
        assert normalized["model_original"] == "some-unknown-model"
        assert normalized["model_mapped"] == "deepseek/deepseek-chat-v3.1:free"

    def test_fallback_to_model_field_when_no_original_model(self):
        """
        Test backward compatibility: if _original_model is not present,
        fall back to the 'model' field.
        """
        log_entry = {
            "timestamp": "2025-10-09T12:00:00.000Z",
            "endpoint": "/v1/chat/completions",
            "status_code": 200,
            "latency_ms": 1000.0,
            "request": {
                # No _original_model field (old logs)
                "model": "gpt-4",
                "messages": [{"role": "user", "content": "Test"}],
            },
            "response": {
                "id": "gen-789",
                "model": "gpt-4",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "Response"},
                    }
                ],
            },
        }

        normalized = _normalize_entry(log_entry)

        assert normalized is not None
        assert normalized["model_original"] == "gpt-4"
        assert normalized["model_mapped"] == "gpt-4"

    def test_original_model_with_error_response(self):
        """
        Test that original model tracking works even when the request fails.
        """
        log_entry = {
            "timestamp": "2025-10-09T12:00:00.000Z",
            "endpoint": "/v1/chat/completions",
            "status_code": 404,
            "latency_ms": 250.75,
            "request": {
                "_original_model": "test-model",
                "model": "deepseek/deepseek-chat-v3.1:free",
                "messages": [{"role": "user", "content": "Test"}],
            },
            "response": {
                "error": {
                    "message": "Model not found",
                    "code": 404,
                }
            },
        }

        normalized = _normalize_entry(log_entry)

        assert normalized is not None
        assert normalized["model_original"] == "test-model"
        assert normalized["model_mapped"] is None  # No model in error response
        assert normalized["status_code"] == 404

    def test_json_serialization_includes_original_model(self):
        """
        Test that the request_json includes both _original_model and model fields.
        """
        log_entry = {
            "timestamp": "2025-10-09T12:00:00.000Z",
            "endpoint": "/v1/chat/completions",
            "status_code": 200,
            "latency_ms": 1000.0,
            "request": {
                "_original_model": "claude-4",
                "model": "anthropic/claude-sonnet-4",
                "messages": [{"role": "user", "content": "Hi"}],
            },
            "response": {
                "id": "gen-999",
                "model": "anthropic/claude-sonnet-4",
                "choices": [
                    {"index": 0, "message": {"role": "assistant", "content": "Hello"}}
                ],
            },
        }

        normalized = _normalize_entry(log_entry)

        assert normalized is not None

        # Parse the stored JSON to verify it contains _original_model
        request_data = json.loads(normalized["request_json"])
        assert "_original_model" in request_data
        assert request_data["_original_model"] == "claude-4"
        assert request_data["model"] == "anthropic/claude-sonnet-4"

    def test_model_original_prefers_original_model_over_model(self):
        """
        Test that model_original field prefers _original_model even when both exist.
        """
        log_entry = {
            "timestamp": "2025-10-09T12:00:00.000Z",
            "endpoint": "/v1/chat/completions",
            "status_code": 200,
            "latency_ms": 1000.0,
            "request": {
                "_original_model": "original-value",
                "model": "mapped-value",
                "messages": [{"role": "user", "content": "Test"}],
            },
            "response": {
                "model": "mapped-value",
                "choices": [],
            },
        }

        normalized = _normalize_entry(log_entry)

        assert normalized is not None
        assert normalized["model_original"] == "original-value"
        assert normalized["model_mapped"] == "mapped-value"
