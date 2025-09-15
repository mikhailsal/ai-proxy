"""
AI Proxy Service

A FastAPI application that proxies requests to various LLM providers
while maintaining OpenAI API compatibility.
"""

# Test comment for repeated deployment verification
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from ai_proxy.logging.config import setup_logging, logger
from ai_proxy.api.v1 import health, models_endpoint, chat_completions

# Initialize logging with file support
import os  # noqa: E402

log_level = os.getenv("LOG_LEVEL", "INFO")
enable_file_logging = os.getenv("ENABLE_FILE_LOGGING", "true").lower() == "true"
setup_logging(log_level=log_level, enable_file_logging=enable_file_logging)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    # Startup
    logger.info("Application startup")
    yield
    # Shutdown (if needed)


app = FastAPI(title="AI Proxy Service", lifespan=lifespan)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific domains
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Include endpoint routers
app.include_router(health.router)
app.include_router(models_endpoint.router)
app.include_router(chat_completions.router)
