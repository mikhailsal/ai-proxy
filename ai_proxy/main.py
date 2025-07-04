from fastapi import FastAPI, Depends, Request
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
import time
from typing import AsyncGenerator
import json

from ai_proxy.logging.config import (
    setup_logging,
    logger,
    log_request_response,
    log_model_usage,
)
from ai_proxy.security.auth import get_api_key
from ai_proxy.core.routing import router
from ai_proxy.core.config import settings

# Path to the deployment timestamp file
DEPLOYMENT_TIMESTAMP_FILE = "/app/deployment-timestamp.txt"

# Initialize logging with file support
setup_logging(log_level="INFO", enable_file_logging=True)

app = FastAPI(title="AI Proxy Service")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific domains
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup_event():
    logger.info("Application startup")


@app.get("/health", tags=["Admin"])
async def health_check():
    """Health check endpoint."""

    deployment_timestamp = "unknown"
    try:
        with open(DEPLOYMENT_TIMESTAMP_FILE, "r") as f:
            deployment_timestamp = f.read().strip()
    except FileNotFoundError:
        logger.warning(
            f"Deployment timestamp file not found at {DEPLOYMENT_TIMESTAMP_FILE}"
        )
    except Exception as e:
        logger.error(f"Error reading deployment timestamp: {e}")

    return {
        "status": "ok",
        "version": "test-final-deployment",
        "script_tested": True,
        "deployment_timestamp": deployment_timestamp,
    }


@app.options("/v1/chat/completions", tags=["API"])
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


@app.post("/v1/chat/completions", tags=["API"])
async def chat_completions(request: Request, api_key: str = Depends(get_api_key)):
    """
    OpenAI-compatible chat completions endpoint.
    """
    start_time = time.time()
    endpoint = request.url.path

    # We get the raw request body to pass it through
    request_data = await request.json()

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
        provider_response = await router.route_chat_completions(request_data, api_key)

        if is_streaming:
            # Handle streaming response
            async def log_and_stream() -> AsyncGenerator[str, None]:
                """Stream response while logging."""
                # Capture current mapped_model value
                current_mapped_model = mapped_model

                collected_response = {
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
                    total_latency_ms = (time.time() - start_time) * 1000
                    status_code = 500
                    error_response = {"error": f"Streaming error: {str(e)}"}

                    logger.error("Error during streaming", exc_info=e)

                    # Log error with full details
                    log.info(
                        "Streaming request failed with internal error",
                        status_code=status_code,
                        mapped_model=current_mapped_model,
                        response_body=error_response,
                        total_latency_ms=round(total_latency_ms),
                        error=str(e),
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
                        mapped_model=current_mapped_model,
                        request_data=request_data,
                        response_data=error_response,
                        status_code=status_code,
                        latency_ms=total_latency_ms,
                        api_key_hash=str(hash(api_key)),
                    )

                    # Send error chunk
                    error_chunk = f'data: {{"error": "Streaming error: {str(e)}"}}\n\ndata: [DONE]\n\n'
                    yield error_chunk

            return StreamingResponse(
                log_and_stream(),
                media_type="text/plain",
                headers={
                    "Cache-Control": "no-cache",
                    "Connection": "keep-alive",
                    "Content-Type": "text/plain; charset=utf-8",
                },
            )
        else:
            # Handle non-streaming response
            # Safely parse JSON response with error handling
            try:
                if provider_response.content:
                    response_body = provider_response.json()
                else:
                    logger.warning("Empty response from provider")
                    response_body = {"error": "Empty response from provider"}
                    status_code = 502
            except ValueError as json_error:
                logger.error(f"Invalid JSON response from provider: {json_error}")
                logger.debug(f"Response content: {provider_response.content}")
                response_body = {"error": "Invalid response from provider"}
                status_code = 502
            else:
                status_code = provider_response.status_code

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
        logger.error("Error processing request", exc_info=e)
        response_body = {"error": "Internal Server Error"}
        status_code = 500

        # Log error for non-streaming requests
        if not is_streaming:
            total_latency_ms = (time.time() - start_time) * 1000

            log.info(
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
        else:
            # For streaming errors, return error response
            return JSONResponse(
                content=response_body,
                status_code=status_code,
            )
