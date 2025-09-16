"""
Validation utilities for API endpoints.
"""

from fastapi.responses import JSONResponse
from typing import Dict, Any

from ai_proxy.logging.config import logger
from ai_proxy.api.v1.models import ChatCompletionRequest


def validate_chat_completion_request(request_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate and parse chat completion request data.

    Args:
        request_data: Raw request data from JSON parsing

    Returns:
        Validated and normalized request data

    Raises:
        ValueError: If validation fails
    """
    try:
        # Validate with Pydantic model
        validated_request = ChatCompletionRequest(**request_data)
        return validated_request.model_dump(exclude_none=True)
    except ValueError as e:
        logger.error(f"Invalid request data: {e}")
        raise ValueError(f"Invalid request: {str(e)}")
    except Exception as e:
        logger.error(f"Failed to parse request: {e}")
        raise ValueError("Malformed JSON in request body")


def create_validation_error_response(error_message: str, error_type: str = "invalid_request_error") -> JSONResponse:
    """
    Create a standardized validation error response.

    Args:
        error_message: The error message to include
        error_type: The type of error (default: invalid_request_error)

    Returns:
        JSONResponse with error details
    """
    return JSONResponse(
        content={
            "error": {
                "message": error_message,
                "type": error_type,
            }
        },
        status_code=400,
    )
