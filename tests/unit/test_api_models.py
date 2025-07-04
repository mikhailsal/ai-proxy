import pytest
from pydantic import ValidationError
from typing import List, Dict, Any

from ai_proxy.api.v1.models import (
    ChatMessage,
    ChatCompletionRequest,
    Choice,
    Usage,
    ChatCompletionResponse,
    DeltaChoice,
    ChatCompletionStreamResponse
)


class TestChatMessage:
    """Test cases for ChatMessage model."""

    def test_chat_message_creation(self):
        """Test basic ChatMessage creation."""
        message = ChatMessage(role="user", content="Hello, world!")
        assert message.role == "user"
        assert message.content == "Hello, world!"

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

    def test_chat_message_validation_required_fields(self):
        """Test ChatMessage validation for required fields."""
        with pytest.raises(ValidationError):
            ChatMessage(role="user")  # Missing content
        
        with pytest.raises(ValidationError):
            ChatMessage(content="Hello")  # Missing role


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
            user="test_user"
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
            another_field=42
        )
        
        assert request.model == "gpt-4"
        assert hasattr(request, 'custom_field')
        assert hasattr(request, 'another_field')

    def test_request_multiple_messages(self):
        """Test ChatCompletionRequest with multiple messages."""
        messages = [
            ChatMessage(role="system", content="You are a helpful assistant"),
            ChatMessage(role="user", content="Hello"),
            ChatMessage(role="assistant", content="Hi there!"),
            ChatMessage(role="user", content="How are you?")
        ]
        request = ChatCompletionRequest(model="gpt-4", messages=messages)
        
        assert len(request.messages) == 4
        assert request.messages[0].role == "system"
        assert request.messages[-1].content == "How are you?"

    def test_request_validation_required_fields(self):
        """Test ChatCompletionRequest validation for required fields."""
        with pytest.raises(ValidationError):
            ChatCompletionRequest(model="gpt-4")  # Missing messages
        
        with pytest.raises(ValidationError):
            ChatCompletionRequest(messages=[])  # Missing model


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

    def test_usage_validation_required_fields(self):
        """Test Usage validation for required fields."""
        with pytest.raises(ValidationError):
            Usage(prompt_tokens=10, completion_tokens=20)  # Missing total_tokens
        
        with pytest.raises(ValidationError):
            Usage(prompt_tokens=10, total_tokens=30)  # Missing completion_tokens


class TestChatCompletionResponse:
    """Test cases for ChatCompletionResponse model."""

    def test_response_creation(self):
        """Test basic ChatCompletionResponse creation."""
        message = ChatMessage(role="assistant", content="Hello!")
        choice = Choice(index=0, message=message, finish_reason="stop")
        usage = Usage(prompt_tokens=10, completion_tokens=5, total_tokens=15)
        
        response = ChatCompletionResponse(
            id="chatcmpl-123",
            object="chat.completion",
            created=1677652288,
            model="gpt-4",
            choices=[choice],
            usage=usage
        )
        
        assert response.id == "chatcmpl-123"
        assert response.object == "chat.completion"
        assert response.created == 1677652288
        assert response.model == "gpt-4"
        assert len(response.choices) == 1
        assert response.choices[0].message.content == "Hello!"
        assert response.usage.total_tokens == 15

    def test_response_multiple_choices(self):
        """Test ChatCompletionResponse with multiple choices."""
        message1 = ChatMessage(role="assistant", content="Response 1")
        message2 = ChatMessage(role="assistant", content="Response 2")
        choice1 = Choice(index=0, message=message1, finish_reason="stop")
        choice2 = Choice(index=1, message=message2, finish_reason="stop")
        usage = Usage(prompt_tokens=10, completion_tokens=10, total_tokens=20)
        
        response = ChatCompletionResponse(
            id="chatcmpl-456",
            object="chat.completion",
            created=1677652288,
            model="gpt-4",
            choices=[choice1, choice2],
            usage=usage
        )
        
        assert len(response.choices) == 2
        assert response.choices[0].message.content == "Response 1"
        assert response.choices[1].message.content == "Response 2"

    def test_response_validation_required_fields(self):
        """Test ChatCompletionResponse validation for required fields."""
        with pytest.raises(ValidationError):
            ChatCompletionResponse(
                object="chat.completion",
                created=1677652288,
                model="gpt-4",
                choices=[],
                usage=Usage(prompt_tokens=10, completion_tokens=5, total_tokens=15)
            )  # Missing id


class TestDeltaChoice:
    """Test cases for DeltaChoice model."""

    def test_delta_choice_creation(self):
        """Test basic DeltaChoice creation."""
        delta_choice = DeltaChoice(
            index=0,
            delta={"role": "assistant", "content": "Hello"},
            finish_reason="stop"
        )
        
        assert delta_choice.index == 0
        assert delta_choice.delta["role"] == "assistant"
        assert delta_choice.delta["content"] == "Hello"
        assert delta_choice.finish_reason == "stop"

    def test_delta_choice_without_finish_reason(self):
        """Test DeltaChoice without finish_reason."""
        delta_choice = DeltaChoice(
            index=0,
            delta={"content": "partial"}
        )
        
        assert delta_choice.index == 0
        assert delta_choice.delta["content"] == "partial"
        assert delta_choice.finish_reason is None

    def test_delta_choice_empty_delta(self):
        """Test DeltaChoice with empty delta."""
        delta_choice = DeltaChoice(index=0, delta={})
        
        assert delta_choice.index == 0
        assert delta_choice.delta == {}

    def test_delta_choice_various_delta_content(self):
        """Test DeltaChoice with various delta content."""
        delta_choice = DeltaChoice(
            index=0,
            delta={
                "role": "assistant",
                "content": "Hello",
                "function_call": {"name": "test", "arguments": "{}"}
            }
        )
        
        assert delta_choice.delta["role"] == "assistant"
        assert delta_choice.delta["content"] == "Hello"
        assert delta_choice.delta["function_call"]["name"] == "test"


class TestChatCompletionStreamResponse:
    """Test cases for ChatCompletionStreamResponse model."""

    def test_stream_response_creation(self):
        """Test basic ChatCompletionStreamResponse creation."""
        delta_choice = DeltaChoice(
            index=0,
            delta={"role": "assistant", "content": "Hello"},
            finish_reason=None
        )
        
        response = ChatCompletionStreamResponse(
            id="chatcmpl-123",
            created=1677652288,
            model="gpt-4",
            choices=[delta_choice]
        )
        
        assert response.id == "chatcmpl-123"
        assert response.object == "chat.completion.chunk"  # Default value
        assert response.created == 1677652288
        assert response.model == "gpt-4"
        assert len(response.choices) == 1
        assert response.choices[0].delta["content"] == "Hello"

    def test_stream_response_custom_object(self):
        """Test ChatCompletionStreamResponse with custom object field."""
        delta_choice = DeltaChoice(index=0, delta={"content": "test"})
        
        response = ChatCompletionStreamResponse(
            id="chatcmpl-456",
            object="custom.chunk",
            created=1677652288,
            model="gpt-4",
            choices=[delta_choice]
        )
        
        assert response.object == "custom.chunk"

    def test_stream_response_multiple_choices(self):
        """Test ChatCompletionStreamResponse with multiple choices."""
        delta_choice1 = DeltaChoice(index=0, delta={"content": "Hello"})
        delta_choice2 = DeltaChoice(index=1, delta={"content": "World"})
        
        response = ChatCompletionStreamResponse(
            id="chatcmpl-789",
            created=1677652288,
            model="gpt-4",
            choices=[delta_choice1, delta_choice2]
        )
        
        assert len(response.choices) == 2
        assert response.choices[0].delta["content"] == "Hello"
        assert response.choices[1].delta["content"] == "World"

    def test_stream_response_validation_required_fields(self):
        """Test ChatCompletionStreamResponse validation for required fields."""
        with pytest.raises(ValidationError):
            ChatCompletionStreamResponse(
                created=1677652288,
                model="gpt-4",
                choices=[]
            )  # Missing id 