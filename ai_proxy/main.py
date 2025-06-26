from fastapi import FastAPI, Depends, Request
from fastapi.responses import JSONResponse
import time

from ai_proxy.logging.config import setup_logging, logger
from ai_proxy.security.auth import get_api_key
from ai_proxy.core.routing import router
from ai_proxy.api.v1.models import ChatCompletionRequest

# Initialize logging
setup_logging()

app = FastAPI(title="AI Proxy Service")

@app.on_event("startup")
async def startup_event():
    logger.info("Application startup")

@app.get("/health", tags=["Admin"])
async def health_check():
    """Health check endpoint."""
    return {"status": "ok"}

@app.post("/v1/chat/completions", tags=["API"])
async def chat_completions(
    request: Request,
    api_key: str = Depends(get_api_key)
):
    """
    OpenAI-compatible chat completions endpoint.
    """
    start_time = time.time()
    
    # We get the raw request body to pass it through
    request_data = await request.json()
    
    log = logger.bind(
        endpoint=request.url.path,
        request_body=request_data
    )
    log.info("Incoming request")

    try:
        provider_response = await router.route_chat_completions(request_data, api_key)
        
        response_body = provider_response.json()
        status_code = provider_response.status_code

    except Exception as e:
        logger.error("Error processing request", exc_info=e)
        return JSONResponse(
            status_code=500,
            content={"error": "Internal Server Error"}
        )
    finally:
        total_latency_ms = (time.time() - start_time) * 1000
        log.info(
            "Request finished",
            status_code=status_code,
            response_body=response_body,
            total_latency_ms=round(total_latency_ms)
        )

    # Return the exact response from the provider
    return JSONResponse(
        content=response_body,
        status_code=status_code,
    )
