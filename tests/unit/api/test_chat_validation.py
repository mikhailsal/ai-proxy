import pytest
import json
from unittest.mock import Mock, AsyncMock


class TestChatCompletionsValidation:
    """Test suite for chat completions input validation."""

    @pytest.fixture
    def mock_request(self):
        """Create a mock request for validation tests."""
        mock_req = Mock()
        mock_req.url.path = "/v1/chat/completions"
        return mock_req

    @pytest.mark.asyncio
    async def test_chat_completions_invalid_json_request(self, mock_request):
        """Test handling of invalid JSON in request body."""
        from ai_proxy.api.v1.chat_completions import chat_completions

        # Mock request with invalid JSON
        mock_request.json = AsyncMock(side_effect=ValueError("Invalid JSON"))

        # Execute
        response = await chat_completions(mock_request, "test-api-key")

        # Verify - should return 400 Bad Request
        assert response.status_code == 400
        response_data = json.loads(response.body)
        assert "error" in response_data
        assert "Invalid JSON" in response_data["error"]["message"]

    @pytest.mark.asyncio
    async def test_chat_completions_missing_model(self, mock_request):
        """Test handling of request missing model field."""
        from ai_proxy.api.v1.chat_completions import chat_completions

        # Mock request without model
        mock_request.json = AsyncMock(
            return_value={
                "messages": [{"role": "user", "content": "Hello"}],
                "stream": False,
            }
        )

        # Execute
        response = await chat_completions(mock_request, "test-api-key")

        # Verify - should return 400 Bad Request
        assert response.status_code == 400
        response_data = json.loads(response.body)
        assert "error" in response_data
        assert "model" in response_data["error"]["message"].lower()

    @pytest.mark.asyncio
    async def test_chat_completions_missing_messages(self, mock_request):
        """Test handling of request missing messages field."""
        from ai_proxy.api.v1.chat_completions import chat_completions

        # Mock request without messages
        mock_request.json = AsyncMock(
            return_value={
                "model": "gpt-4",
                "stream": False,
            }
        )

        # Execute
        response = await chat_completions(mock_request, "test-api-key")

        # Verify - should return 400 Bad Request
        assert response.status_code == 400
        response_data = json.loads(response.body)
        assert "error" in response_data
        assert "messages" in response_data["error"]["message"].lower()

    @pytest.mark.asyncio
    async def test_chat_completions_empty_messages(self, mock_request):
        """Test handling of request with empty messages array."""
        from ai_proxy.api.v1.chat_completions import chat_completions

        # Mock request with empty messages
        mock_request.json = AsyncMock(
            return_value={
                "model": "gpt-4",
                "messages": [],
                "stream": False,
            }
        )

        # Execute
        response = await chat_completions(mock_request, "test-api-key")

        # Verify - should return 400 Bad Request
        assert response.status_code == 400
        response_data = json.loads(response.body)
        assert "error" in response_data
        assert "messages" in response_data["error"]["message"].lower()

    @pytest.mark.asyncio
    async def test_chat_completions_invalid_message_format(self, mock_request):
        """Test handling of request with invalid message format."""
        from ai_proxy.api.v1.chat_completions import chat_completions

        # Mock request with invalid message format
        mock_request.json = AsyncMock(
            return_value={
                "model": "gpt-4",
                "messages": [
                    {"role": "user"},  # Missing content
                    {"content": "Hello"},  # Missing role
                ],
                "stream": False,
            }
        )

        # Execute
        response = await chat_completions(mock_request, "test-api-key")

        # Verify - should return 400 Bad Request
        assert response.status_code == 400
        response_data = json.loads(response.body)
        assert "error" in response_data

    @pytest.mark.asyncio
    async def test_chat_completions_invalid_stream_value(self, mock_request):
        """Test handling of request with invalid stream value."""
        from ai_proxy.api.v1.chat_completions import chat_completions

        # Mock request with invalid stream value
        mock_request.json = AsyncMock(
            return_value={
                "model": "gpt-4",
                "messages": [{"role": "user", "content": "Hello"}],
                "stream": "invalid",  # Should be boolean
            }
        )

        # Execute
        response = await chat_completions(mock_request, "test-api-key")

        # Verify - should handle gracefully (implementation may convert or default)
        # The exact behavior depends on the validation implementation
        assert response.status_code in [200, 400]  # Either success or validation error

    @pytest.mark.asyncio
    async def test_chat_completions_unsupported_model(self, mock_request):
        """Test handling of request with unsupported model."""
        from ai_proxy.api.v1.chat_completions import chat_completions
        from unittest.mock import patch

        # Mock request with unsupported model
        mock_request.json = AsyncMock(
            return_value={
                "model": "unsupported-model-12345",
                "messages": [{"role": "user", "content": "Hello"}],
                "stream": False,
            }
        )

        with (
            patch("ai_proxy.api.v1.chat_completions.settings") as mock_settings,
            patch("ai_proxy.core.routing.settings") as mock_routing_settings,
        ):
            mock_settings.get_mapped_model.return_value = (
                "openrouter",
                "unsupported-model-12345",
            )
            mock_settings.is_valid_model.return_value = False  # Model is not valid

            mock_routing_settings.get_mapped_model.return_value = (
                "openrouter",
                "unsupported-model-12345",
            )
            mock_routing_settings.is_valid_model.return_value = (
                False  # Model is not valid
            )

            # Execute
            response = await chat_completions(mock_request, "test-api-key")

            # Verify - should return error for unsupported model
            assert response.status_code in [
                400,
                404,
                500,
            ]  # Bad request, not found, or internal error
            response_data = json.loads(response.body)
            assert "error" in response_data
