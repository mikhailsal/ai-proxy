"""
Error handling utilities for API endpoints.
"""

from fastapi.responses import JSONResponse
import time
from typing import Dict, Any

from ai_proxy.logging.config import (
    logger,
    log_request_response,
    log_model_usage,
)


def handle_streaming_error(
    error: Exception,
    start_time: float,
    endpoint: str,
    request_data: Dict[str, Any],
    original_model: str,
    mapped_model: str,
    api_key: str,
) -> str:
    """
    Handle errors during streaming response processing.

    Args:
        error: The exception that occurred
        start_time: Request start timestamp
        endpoint: API endpoint path
        request_data: Original request data
        original_model: Original model name from request
        mapped_model: Mapped model name
        api_key: API key for logging

    Returns:
        Error chunk string for streaming response
    """
    total_latency_ms = (time.time() - start_time) * 1000
    status_code = 500
    error_response = {"error": f"Streaming error: {str(error)}"}

    logger.error("Error during streaming", exc_info=error)

    # Log error with full details
    logger.info(
        "Streaming request failed with internal error",
        status_code=status_code,
        mapped_model=mapped_model,
        response_body=error_response,
        total_latency_ms=round(total_latency_ms),
        error=str(error),
    )

    # Log to endpoint-specific log file
    log_request_response(
        endpoint=endpoint,
        request_data=request_data,
        response_data=error_response,
        status_code=status_code,
        latency_ms=total_latency_ms,
        api_key_hash=str(hash(api_key)),
    )

    # Log to model-specific log files
    log_model_usage(
        original_model=original_model,
        mapped_model=mapped_model,
        request_data=request_data,
        response_data=error_response,
        status_code=status_code,
        latency_ms=total_latency_ms,
        api_key_hash=str(hash(api_key)),
    )

    # Return error chunk for streaming response
    error_chunk = (
        f'data: {{"error": "Streaming error: {str(error)}"}}\n\ndata: [DONE]\n\n'
    )
    return error_chunk


def validate_provider_response(provider_response) -> tuple[Dict[str, Any], int]:
    """
    Validate and extract data from provider response.

    Args:
        provider_response: Response object from provider

    Returns:
        Tuple of (response_body, status_code)

    Raises:
        ValueError: If response validation fails
    """
    # Validate response object structure
    if not hasattr(provider_response, "status_code") or not hasattr(
        provider_response, "content"
    ):
        raise ValueError("Expected httpx.Response-like object for non-streaming")

    if not hasattr(provider_response, "json"):
        raise ValueError("Response object should have json method")

    try:
        if not provider_response.content:
            logger.warning("Empty response from provider")
            response_body = {"error": "Empty response from provider"}
        else:
            response_body = provider_response.json()
    except ValueError as json_error:
        logger.error(f"Invalid JSON response from provider: {json_error}")
        logger.debug(f"Response content: {provider_response.content!r}")
        response_body = {"error": "Invalid response from provider"}
        status_code = 502
        return response_body, status_code

    status_code = provider_response.status_code
    return response_body, status_code


def handle_request_error(
    error: Exception,
    start_time: float,
    endpoint: str,
    request_data: Dict[str, Any],
    original_model: str,
    mapped_model: str,
    api_key: str,
    is_streaming: bool,
) -> JSONResponse:
    """
    Handle general request processing errors.

    Args:
        error: The exception that occurred
        start_time: Request start timestamp
        endpoint: API endpoint path
        request_data: Original request data
        original_model: Original model name from request
        mapped_model: Mapped model name
        api_key: API key for logging
        is_streaming: Whether this was a streaming request

    Returns:
        JSONResponse with error details
    """
    logger.error("Error processing request", exc_info=error)
    response_body = {"error": "Internal Server Error"}
    status_code = 500

    # Log error for non-streaming requests
    if not is_streaming:
        total_latency_ms = (time.time() - start_time) * 1000

        logger.info(
            "Request finished",
            status_code=status_code,
            mapped_model=mapped_model,
            response_body=response_body,
            total_latency_ms=round(total_latency_ms),
        )

    return JSONResponse(
        content=response_body,
        status_code=status_code,
    )


def create_internal_error_response() -> JSONResponse:
    """
    Create a standardized internal server error response.

    Returns:
        JSONResponse with internal error details
    """
    return JSONResponse(
        content={"error": "Internal Server Error"},
        status_code=500,
    )
