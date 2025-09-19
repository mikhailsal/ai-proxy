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
                        # Log raw incoming SSE chunk for debugging (helps verify provider output)
                        try:
                            log.info("Streaming chunk received (raw)", raw_chunk=chunk)
                        except Exception:
                            # Ensure logging failure doesn't break streaming
                            pass

                        # Stream out exactly what we receive (already SSE-formatted)
                        yield chunk

                        # Parse SSE lines to collect response data for logging
                        if not chunk:
                            continue

                        try:
                            # An httpx stream "chunk" may contain multiple SSE events.
                            # We must split by lines and handle each 'data: ' entry.
                            for line in chunk.split("\n"):
                                if not line:
                                    continue

                                if not line.startswith("data: "):
                                    continue

                                data_content = line[6:].strip()

                                # Handle [DONE]
                                if data_content == "[DONE]":
                                    continue

                                # Try to parse JSON for a completion chunk
                                parsed_chunk = json.loads(data_content)
                                if not isinstance(parsed_chunk, dict):
                                    continue

                                # Provider-side error chunk passthrough
                                if "error" in parsed_chunk:
                                    error_occurred = True
                                    error_response = parsed_chunk
                                    # Stop collecting further
                                    break

                                # Update collected response meta
                                if "id" in parsed_chunk:
                                    collected_response["id"] = parsed_chunk["id"]
                                if "created" in parsed_chunk:
                                    collected_response["created"] = parsed_chunk[
                                        "created"
                                    ]
                                if "model" in parsed_chunk:
                                    collected_response["model"] = parsed_chunk["model"]
                                    current_mapped_model = parsed_chunk["model"]

                                # Accumulate content from choices[*].delta.content
                                choices = parsed_chunk.get("choices") or []
                                if choices and isinstance(choices, list):
                                    first_choice = choices[0]
                                    if isinstance(first_choice, dict):
                                        delta = first_choice.get("delta") or {}
                                        # Some providers may stream role first; ignore if no content
                                        content_piece = delta.get("content")
                                        if isinstance(content_piece, str):
                                            collected_response["choices"][0]["message"][
                                                "content"
                                            ] += content_piece

                                        if first_choice.get("finish_reason"):
                                            collected_response["choices"][0][
                                                "finish_reason"
                                            ] = first_choice["finish_reason"]
                        except (
                            json.JSONDecodeError,
                            KeyError,
                            IndexError,
                            AssertionError,
                        ):
                            # Ignore malformed or partial lines; continue streaming
                            continue

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
