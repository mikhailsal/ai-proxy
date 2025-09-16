import pytest
from pydantic import ValidationError

from ai_proxy.api.v1.models import (
    ChatMessage,
    ChatCompletionRequest,
    Usage,
)


class TestChatMessageValidation:
    """Test cases for ChatMessage validation."""

    def test_chat_message_validation_required_fields(self):
        """Test ChatMessage validation for required fields."""
        with pytest.raises(ValidationError):
            ChatMessage(role="user")  # Missing content

        with pytest.raises(ValidationError):
            ChatMessage(content="Hello")  # Missing role


class TestChatCompletionRequestValidation:
    """Test cases for ChatCompletionRequest validation."""

    def test_request_validation_required_fields(self):
        """Test ChatCompletionRequest validation for required fields."""
        with pytest.raises(ValidationError):
            ChatCompletionRequest(model="gpt-4")  # Missing messages

        with pytest.raises(ValidationError):
            ChatCompletionRequest(messages=[])  # Missing model


class TestUsageValidation:
    """Test cases for Usage validation."""

    def test_usage_validation_required_fields(self):
        """Test Usage validation for required fields."""
        with pytest.raises(ValidationError):
            Usage(prompt_tokens=10, completion_tokens=20)  # Missing total_tokens

        with pytest.raises(ValidationError):
            Usage(prompt_tokens=10, total_tokens=30)  # Missing completion_tokens


class TestChatCompletionResponseValidation:
    """Test cases for ChatCompletionResponse validation."""

    def test_response_validation_required_fields(self):
        """Test ChatCompletionResponse validation for required fields."""
        from ai_proxy.api.v1.models import ChatCompletionResponse, ChatMessage, Choice, Usage

        with pytest.raises(ValidationError):
            ChatCompletionResponse(
                object="chat.completion",
                created=1677652288,
                model="gpt-4",
                choices=[],
                usage=Usage(prompt_tokens=10, completion_tokens=5, total_tokens=15),
            )  # Missing id


class TestChatCompletionStreamResponseValidation:
    """Test cases for ChatCompletionStreamResponse validation."""

    def test_stream_response_validation_required_fields(self):
        """Test ChatCompletionStreamResponse validation for required fields."""
        from ai_proxy.api.v1.models import ChatCompletionStreamResponse

        with pytest.raises(ValidationError):
            ChatCompletionStreamResponse(
                created=1677652288, model="gpt-4", choices=[]
            )  # Missing id
