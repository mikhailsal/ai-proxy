from fastapi import FastAPI, Depends, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import time

from ai_proxy.logging.config import (
    setup_logging, logger, log_request_response, log_model_usage
)
from ai_proxy.security.auth import get_api_key
from ai_proxy.core.routing import router

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
    return {"status": "ok"}


@app.options("/v1/chat/completions", tags=["API"])
async def chat_completions_options():
    """Handle CORS preflight requests for chat completions."""
    return JSONResponse(
        content={},
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
            "Access-Control-Max-Age": "86400"
        }
    )


@app.post("/v1/chat/completions", tags=["API"])
async def chat_completions(
    request: Request,
    api_key: str = Depends(get_api_key)
):
    """
    OpenAI-compatible chat completions endpoint.
    """
    start_time = time.time()
    endpoint = request.url.path
    
    # We get the raw request body to pass it through
    request_data = await request.json()
    
    # Extract model information for logging
    original_model = request_data.get("model", "unknown")
    
    log = logger.bind(
        endpoint=endpoint,
        original_model=original_model,
        request_body=request_data
    )
    log.info("Incoming request")

    status_code = 500
    response_body = {"error": "Internal Server Error"}
    mapped_model = original_model

    try:
        provider_response = await router.route_chat_completions(
            request_data, api_key
        )
        
        response_body = provider_response.json()
        status_code = provider_response.status_code
        
        # Extract mapped model from response if available
        if isinstance(response_body, dict) and "model" in response_body:
            mapped_model = response_body["model"]

    except Exception as e:
        logger.error("Error processing request", exc_info=e)
        response_body = {"error": "Internal Server Error"}
        status_code = 500
    finally:
        total_latency_ms = (time.time() - start_time) * 1000
        
        # Log to main application log
        log.info(
            "Request finished",
            status_code=status_code,
            mapped_model=mapped_model,
            response_body=response_body,
            total_latency_ms=round(total_latency_ms)
        )
        
        # Log to endpoint-specific log file
        log_request_response(
            endpoint=endpoint,
            request_data=request_data,
            response_data=response_body,
            status_code=status_code,
            latency_ms=total_latency_ms,
            api_key_hash=str(hash(api_key))
        )
        
        # Log to model-specific log files
        log_model_usage(
            original_model=original_model,
            mapped_model=mapped_model,
            request_data=request_data,
            response_data=response_body,
            status_code=status_code,
            latency_ms=total_latency_ms,
            api_key_hash=str(hash(api_key))
        )

    # Return the exact response from the provider
    return JSONResponse(
        content=response_body,
        status_code=status_code,
    )
