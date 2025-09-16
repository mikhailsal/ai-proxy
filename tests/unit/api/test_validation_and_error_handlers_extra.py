import pytest


def test_validate_chat_completion_request_handles_unexpected_exception(monkeypatch):
    """When the underlying model constructor raises a non-ValueError exception,
    the validator should convert it into a generic malformed JSON ValueError.
    """
    # Replace the ChatCompletionRequest with a constructor that raises Exception
    class BadConstructor:
        def __init__(self, *args, **kwargs):
            raise Exception("parse failure")

    monkeypatch.setattr("ai_proxy.api.v1.validation.ChatCompletionRequest", BadConstructor)

    from ai_proxy.api.v1.validation import validate_chat_completion_request

    with pytest.raises(ValueError) as exc:
        validate_chat_completion_request({})

    assert str(exc.value) == "Malformed JSON in request body"


def test_validate_chat_completion_request_propagates_validation_errors(monkeypatch):
    """If the model raises ValueError (validation error), the message should be included."""
    class BadConstructor:
        def __init__(self, *args, **kwargs):
            raise ValueError("missing field: messages")

    monkeypatch.setattr("ai_proxy.api.v1.validation.ChatCompletionRequest", BadConstructor)
    from ai_proxy.api.v1.validation import validate_chat_completion_request

    with pytest.raises(ValueError) as exc:
        validate_chat_completion_request({})

    assert "Invalid request: missing field: messages" in str(exc.value)


def test_validate_provider_response_missing_attributes_raises():
    from ai_proxy.api.v1.error_handlers import validate_provider_response

    class Missing:
        pass

    with pytest.raises(ValueError) as exc:
        validate_provider_response(Missing())

    assert "Expected httpx.Response-like object" in str(exc.value)


def test_validate_provider_response_missing_json_method_raises():
    from ai_proxy.api.v1.error_handlers import validate_provider_response

    class Resp:
        status_code = 200
        content = b"{}"

    with pytest.raises(ValueError) as exc:
        validate_provider_response(Resp())

    assert "Response object should have json method" in str(exc.value)


def test_create_internal_error_response_returns_500():
    from ai_proxy.api.v1.error_handlers import create_internal_error_response

    resp = create_internal_error_response()
    assert resp.status_code == 500
    # JSONResponse renders bytes when accessed
    assert b"Internal Server Error" in resp.body


