"""
Chat completions endpoint.
"""

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, StreamingResponse
import time
from typing import AsyncGenerator, Dict, Any
import json

from ai_proxy.logging.config import (
    logger,
    log_request_response,
    log_model_usage,
)
from ai_proxy.security.auth import get_api_key
from ai_proxy.core.routing import router as routing_router
from ai_proxy.core.config import settings
from ai_proxy.api.v1.validation import (
    validate_chat_completion_request,
    create_validation_error_response,
)
from ai_proxy.api.v1.error_handlers import (
    handle_streaming_error,
    validate_provider_response,
    handle_request_error,
)

router = APIRouter(tags=["API"])


@router.options("/v1/chat/completions")
async def chat_completions_options():
    """Handle CORS preflight requests for chat completions."""
    return JSONResponse(
        content={},
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
            "Access-Control-Max-Age": "86400",
        },
    )


@router.post("/v1/chat/completions")
async def chat_completions(request: Request, api_key: str = Depends(get_api_key)):
    """
    OpenAI-compatible chat completions endpoint.
    """
    start_time = time.time()
    endpoint = request.url.path

    # Parse and validate request body
    try:
        raw_request_data = await request.json()
        request_data = validate_chat_completion_request(raw_request_data)
    except ValueError as e:
        return create_validation_error_response(str(e))

    # Extract model information for logging
    original_model = request_data.get("model", "unknown")
    is_streaming = request_data.get("stream", False)

    # Get mapped model for logging
    provider, mapped_model = settings.get_mapped_model(original_model)

    log = logger.bind(
        endpoint=endpoint,
        original_model=original_model,
        streaming=is_streaming,
        request_body=request_data,
    )
    log.info("Incoming request")

    status_code = 500
    response_body = {"error": "Internal Server Error"}

    try:
        provider_response = await routing_router.route_chat_completions(
            request_data, api_key
        )

        if is_streaming:
            # Handle streaming response
            async def log_and_stream() -> AsyncGenerator[str, None]:
                """Stream response while logging."""
                # Capture current mapped_model value
                current_mapped_model = mapped_model

                collected_response: Dict[str, Any] = {
                    "id": "",
                    "object": "chat.completion",
                    "created": 0,
                    "model": current_mapped_model,
                    "choices": [
                        {
                            "index": 0,
                            "message": {"role": "assistant", "content": ""},
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": {
                        "prompt_tokens": 0,
                        "completion_tokens": 0,
                        "total_tokens": 0,
                    },
                }

                error_occurred = False
                error_response = None

                try:
                    # Type check to ensure we can iterate over the response
                    if not hasattr(provider_response, "__aiter__"):
                        raise ValueError(
                            "Expected async generator for streaming response"
                        )
                    async for chunk in provider_response:
                        yield chunk

                        # Parse chunk to collect response data for logging
                        if chunk.strip() and not chunk.strip() == "data: [DONE]":
                            try:
                                # Extract JSON from SSE format
                                if chunk.startswith("data: "):
                                    chunk_data = chunk[6:].strip()
                                    if chunk_data and chunk_data != "[DONE]":
                                        parsed_chunk = json.loads(chunk_data)
                                        assert isinstance(parsed_chunk, dict), (
                                            "Expected dict from JSON parse"
                                        )

                                        # Check for error in chunk
                                        if "error" in parsed_chunk:
                                            error_occurred = True
                                            error_response = parsed_chunk
                                            break

                                        # Update collected response with chunk data
                                        if "id" in parsed_chunk:
                                            collected_response["id"] = parsed_chunk[
                                                "id"
                                            ]
                                        if "created" in parsed_chunk:
                                            collected_response["created"] = (
                                                parsed_chunk["created"]
                                            )
                                        if "model" in parsed_chunk:
                                            collected_response["model"] = parsed_chunk[
                                                "model"
                                            ]
                                            current_mapped_model = parsed_chunk["model"]

                                        # Collect content from delta
                                        if (
                                            "choices" in parsed_chunk
                                            and parsed_chunk["choices"]
                                        ):
                                            choice = parsed_chunk["choices"][0]
                                            assert isinstance(choice, dict), (
                                                "Expected dict for choice"
                                            )
                                            if (
                                                "delta" in choice
                                                and "content" in choice["delta"]
                                            ):
                                                collected_response["choices"][0][
                                                    "message"
                                                ]["content"] += choice["delta"][
                                                    "content"
                                                ]
                                            if (
                                                "finish_reason" in choice
                                                and choice["finish_reason"]
                                            ):
                                                collected_response["choices"][0][
                                                    "finish_reason"
                                                ] = choice["finish_reason"]
                            except (json.JSONDecodeError, KeyError, IndexError):
                                # Skip malformed chunks
                                pass

                    # Determine final status and response
                    if error_occurred and error_response:
                        status_code = error_response.get("error", {}).get("code", 500)
                        final_response = error_response
                        log_message = "Streaming request failed with provider error"
                    else:
                        status_code = 200
                        final_response = collected_response
                        log_message = "Streaming request completed successfully"

                    # Log completion with full details
                    total_latency_ms = (time.time() - start_time) * 1000

                    log.info(
                        log_message,
                        status_code=status_code,
                        mapped_model=current_mapped_model,
                        response_body=final_response,
                        total_latency_ms=round(total_latency_ms),
                    )

                    # Log to endpoint-specific log file
                    log_request_response(
                        endpoint=endpoint,
                        request_data=request_data,
                        response_data=final_response,
                        status_code=status_code,
                        latency_ms=total_latency_ms,
                        api_key_hash=str(hash(api_key)),
                    )

                    # Log to model-specific log files
                    log_model_usage(
                        original_model=original_model,
                        mapped_model=current_mapped_model,
                        request_data=request_data,
                        response_data=final_response,
                        status_code=status_code,
                        latency_ms=total_latency_ms,
                        api_key_hash=str(hash(api_key)),
                    )

                except Exception as e:
                    # Yield error chunk and stop processing
                    error_chunk = handle_streaming_error(
                        e,
                        start_time,
                        endpoint,
                        request_data,
                        original_model,
                        current_mapped_model,
                        api_key,
                    )
                    yield error_chunk
                    return

            return StreamingResponse(
                log_and_stream(),
                media_type="text/event-stream",
                headers={
                    "Cache-Control": "no-cache",
                    "Connection": "keep-alive",
                    "Content-Type": "text/event-stream",
                },
            )
        else:
            # Handle non-streaming response
            response_body, status_code = validate_provider_response(provider_response)

            # Extract mapped model from response if available
            if isinstance(response_body, dict) and "model" in response_body:
                mapped_model = response_body["model"]

            # Log for non-streaming requests
            total_latency_ms = (time.time() - start_time) * 1000

            # Log to main application log
            log.info(
                "Request finished",
                status_code=status_code,
                mapped_model=mapped_model,
                response_body=response_body,
                total_latency_ms=round(total_latency_ms),
            )

            # Log to endpoint-specific log file
            log_request_response(
                endpoint=endpoint,
                request_data=request_data,
                response_data=response_body,
                status_code=status_code,
                latency_ms=total_latency_ms,
                api_key_hash=str(hash(api_key)),
            )

            # Log to model-specific log files
            log_model_usage(
                original_model=original_model,
                mapped_model=mapped_model,
                request_data=request_data,
                response_data=response_body,
                status_code=status_code,
                latency_ms=total_latency_ms,
                api_key_hash=str(hash(api_key)),
            )

            # Return the exact response from the provider
            return JSONResponse(
                content=response_body,
                status_code=status_code,
            )

    except Exception as e:
        return handle_request_error(
            e,
            start_time,
            endpoint,
            request_data,
            original_model,
            mapped_model,
            api_key,
            is_streaming,
        )
