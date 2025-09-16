import pytest
from pydantic import ValidationError

from ai_proxy.api.v1.models import (
    ChatMessage,
    ChatCompletionRequest,
    Choice,
    Usage,
)


class TestChatMessage:
    """Test cases for ChatMessage model."""

    def test_chat_message_creation(self):
        """Test basic ChatMessage creation."""
        message = ChatMessage(role="user", content="Hello, world!")
        assert message.role == "user"
        assert message.content == "Hello, world!"

    def test_chat_message_with_string_content(self):
        """Test ChatMessage with traditional string content."""
        message = ChatMessage(role="user", content="Simple string message")

        assert message.role == "user"
        assert message.content == "Simple string message"

    def test_chat_message_with_array_content(self):
        """Test ChatMessage with new array content format."""
        content_array = [
            {"type": "text", "text": "Hello"},
            {"type": "text", "text": "World"},
        ]
        message = ChatMessage(role="user", content=content_array)

        assert message.role == "user"
        assert message.content == "Hello World"  # Should be joined with spaces

    def test_chat_message_with_single_text_object(self):
        """Test ChatMessage with single text object in array."""
        content_array = [{"type": "text", "text": "Single text message"}]
        message = ChatMessage(role="user", content=content_array)

        assert message.role == "user"
        assert message.content == "Single text message"

    def test_chat_message_with_mixed_content_types(self):
        """Test ChatMessage with mixed content types in array."""
        content_array = [
            {"type": "text", "text": "Text part"},
            {
                "type": "image",
                "url": "http://example.com/image.jpg",
            },  # Should be ignored
            {"type": "text", "text": "More text"},
        ]
        message = ChatMessage(role="user", content=content_array)

        assert message.role == "user"
        assert (
            message.content == "Text part More text"
        )  # Only text parts should be included

    def test_chat_message_with_empty_array(self):
        """Test ChatMessage with empty content array."""
        message = ChatMessage(role="user", content=[])

        assert message.role == "user"
        assert message.content == ""  # Should be empty string

    def test_chat_message_with_non_dict_items(self):
        """Test ChatMessage with non-dict items in array."""
        content_array = ["string item", 123, {"type": "text", "text": "Valid text"}]
        message = ChatMessage(role="user", content=content_array)

        assert message.role == "user"
        assert (
            message.content == "string item 123 Valid text"
        )  # All converted to strings

    def test_chat_message_different_roles(self):
        """Test ChatMessage with different roles."""
        user_msg = ChatMessage(role="user", content="User message")
        assistant_msg = ChatMessage(role="assistant", content="Assistant response")
        system_msg = ChatMessage(role="system", content="System prompt")

        assert user_msg.role == "user"
        assert assistant_msg.role == "assistant"
        assert system_msg.role == "system"

    def test_chat_message_empty_content(self):
        """Test ChatMessage with empty content."""
        message = ChatMessage(role="user", content="")
        assert message.content == ""


class TestChatCompletionRequest:
    """Test cases for ChatCompletionRequest model."""

    def test_minimal_request(self):
        """Test minimal ChatCompletionRequest."""
        messages = [ChatMessage(role="user", content="Hello")]
        request = ChatCompletionRequest(model="gpt-4", messages=messages)

        assert request.model == "gpt-4"
        assert len(request.messages) == 1
        assert request.messages[0].role == "user"
        assert request.stream is False  # Default value

    def test_request_with_all_optional_fields(self):
        """Test ChatCompletionRequest with all optional fields."""
        messages = [ChatMessage(role="user", content="Hello")]
        request = ChatCompletionRequest(
            model="gpt-4",
            messages=messages,
            temperature=0.7,
            top_p=0.9,
            n=2,
            stream=True,
            stop=["END", "STOP"],
            max_tokens=100,
            presence_penalty=0.1,
            frequency_penalty=0.2,
            logit_bias={"token1": 0.5, "token2": -0.3},
            user="test_user",
        )

        assert request.temperature == 0.7
        assert request.top_p == 0.9
        assert request.n == 2
        assert request.stream is True
        assert request.stop == ["END", "STOP"]
        assert request.max_tokens == 100
        assert request.presence_penalty == 0.1
        assert request.frequency_penalty == 0.2
        assert request.logit_bias == {"token1": 0.5, "token2": -0.3}
        assert request.user == "test_user"

    def test_request_extra_fields_allowed(self):
        """Test that extra fields are allowed in ChatCompletionRequest."""
        messages = [ChatMessage(role="user", content="Hello")]
        request = ChatCompletionRequest(
            model="gpt-4",
            messages=messages,
            custom_field="custom_value",
            another_field=42,
        )

        assert request.model == "gpt-4"
        assert hasattr(request, "custom_field")
        assert hasattr(request, "another_field")

    def test_request_multiple_messages(self):
        """Test ChatCompletionRequest with multiple messages."""
        messages = [
            ChatMessage(role="system", content="You are a helpful assistant"),
            ChatMessage(role="user", content="Hello"),
            ChatMessage(role="assistant", content="Hi there!"),
            ChatMessage(role="user", content="How are you?"),
        ]
        request = ChatCompletionRequest(model="gpt-4", messages=messages)

        assert len(request.messages) == 4
        assert request.messages[0].role == "system"
        assert request.messages[-1].content == "How are you?"


class TestChoice:
    """Test cases for Choice model."""

    def test_choice_creation(self):
        """Test basic Choice creation."""
        message = ChatMessage(role="assistant", content="Hello!")
        choice = Choice(index=0, message=message, finish_reason="stop")

        assert choice.index == 0
        assert choice.message.role == "assistant"
        assert choice.message.content == "Hello!"
        assert choice.finish_reason == "stop"

    def test_choice_without_finish_reason(self):
        """Test Choice without finish_reason (optional field)."""
        message = ChatMessage(role="assistant", content="Hello!")
        choice = Choice(index=0, message=message)

        assert choice.index == 0
        assert choice.finish_reason is None

    def test_choice_different_finish_reasons(self):
        """Test Choice with different finish_reason values."""
        message = ChatMessage(role="assistant", content="Hello!")

        choice1 = Choice(index=0, message=message, finish_reason="stop")
        choice2 = Choice(index=1, message=message, finish_reason="length")
        choice3 = Choice(index=2, message=message, finish_reason="content_filter")

        assert choice1.finish_reason == "stop"
        assert choice2.finish_reason == "length"
        assert choice3.finish_reason == "content_filter"


class TestUsage:
    """Test cases for Usage model."""

    def test_usage_creation(self):
        """Test basic Usage creation."""
        usage = Usage(prompt_tokens=10, completion_tokens=20, total_tokens=30)

        assert usage.prompt_tokens == 10
        assert usage.completion_tokens == 20
        assert usage.total_tokens == 30

    def test_usage_zero_values(self):
        """Test Usage with zero values."""
        usage = Usage(prompt_tokens=0, completion_tokens=0, total_tokens=0)

        assert usage.prompt_tokens == 0
        assert usage.completion_tokens == 0
        assert usage.total_tokens == 0
