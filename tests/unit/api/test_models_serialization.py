from ai_proxy.api.v1.models import (
    ChatMessage,
    ChatCompletionResponse,
    Choice,
    Usage,
    DeltaChoice,
    ChatCompletionStreamResponse,
)


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
            usage=usage,
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
            usage=usage,
        )

        assert len(response.choices) == 2
        assert response.choices[0].message.content == "Response 1"
        assert response.choices[1].message.content == "Response 2"


class TestDeltaChoice:
    """Test cases for DeltaChoice model."""

    def test_delta_choice_creation(self):
        """Test basic DeltaChoice creation."""
        delta_choice = DeltaChoice(
            index=0,
            delta={"role": "assistant", "content": "Hello"},
            finish_reason="stop",
        )

        assert delta_choice.index == 0
        assert delta_choice.delta["role"] == "assistant"
        assert delta_choice.delta["content"] == "Hello"
        assert delta_choice.finish_reason == "stop"

    def test_delta_choice_without_finish_reason(self):
        """Test DeltaChoice without finish_reason."""
        delta_choice = DeltaChoice(index=0, delta={"content": "partial"})

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
                "function_call": {"name": "test", "arguments": "{}"},
            },
        )

        assert delta_choice.delta["role"] == "assistant"
        assert delta_choice.delta["content"] == "Hello"
        assert delta_choice.delta["function_call"]["name"] == "test"


class TestChatCompletionStreamResponse:
    """Test cases for ChatCompletionStreamResponse model."""

    def test_stream_response_creation(self):
        """Test basic ChatCompletionStreamResponse creation."""
        delta_choice = DeltaChoice(
            index=0, delta={"role": "assistant", "content": "Hello"}, finish_reason=None
        )

        response = ChatCompletionStreamResponse(
            id="chatcmpl-123", created=1677652288, model="gpt-4", choices=[delta_choice]
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
            choices=[delta_choice],
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
            choices=[delta_choice1, delta_choice2],
        )

        assert len(response.choices) == 2
        assert response.choices[0].delta["content"] == "Hello"
        assert response.choices[1].delta["content"] == "World"
