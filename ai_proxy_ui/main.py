from fastapi import FastAPI, APIRouter, Depends, HTTPException, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.openapi.docs import get_swagger_ui_html
import os
import time
import uuid
import base64
import datetime as _dt
import sqlite3
from typing import Literal, Optional, List, Tuple
import json

# Refactored helpers and auth dependency
from ai_proxy_ui.config import _get_allowed_origins, _get_bool_env, _get_csv_env, API_VERSION
from ai_proxy_ui.services import auth as auth_service
from ai_proxy_ui.routers import requests as requests_router


# Use config helpers imported from `ai_proxy_ui.config`

app = FastAPI(
    title="AI Proxy Logs UI API",
    openapi_url="/ui/v1/openapi.json",
    docs_url=("/ui/v1/docs" if os.getenv("ENVIRONMENT", "development").strip().lower() != "production" else None),
    redoc_url=None,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=_get_allowed_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Standard headers + request ID middleware
@app.middleware("http")
async def add_standard_headers(request: Request, call_next):
    request_id = str(uuid.uuid4())
    request.state.request_id = request_id
    response = await call_next(request)
    response.headers["X-API-Version"] = API_VERSION
    response.headers["X-Request-Id"] = request_id
    return response


# Error handler to standardize error responses
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "code": exc.status_code,
            "message": exc.detail if isinstance(exc.detail, str) else str(exc.detail),
            "requestId": request_id,
        },
    )


# Simple per-key, per-path rate limiter (fixed window per second)
_rate_limit_rps_default = 10


# Use centralized auth helpers from `ai_proxy_ui.services.auth`
# This avoids duplicating state (rate limiter buckets) across modules and ensures
# a single source of truth for authentication and rate limiting.
_rate_limit_rps_default = 10


@app.get("/ui/health")
async def health_legacy():
    return {"status": "ok"}


v1 = APIRouter(prefix="/ui/v1", dependencies=[Depends(auth_service._require_auth())])


@v1.get("/health")
async def health_v1():
    return {"status": "ok"}


@v1.get("/config")
async def get_config():
    features = {
        "fts_enabled": _get_bool_env("LOGDB_FTS_ENABLED", False),
        "text_logs_enabled": _get_bool_env("LOGUI_ENABLE_TEXT_LOGS", False),
        "admin_enabled": len(_get_csv_env("LOGUI_ADMIN_API_KEYS")) > 0,
    }
    try:
        rps = int(os.getenv("LOGUI_RATE_LIMIT_RPS", "10"))
    except ValueError:
        rps = 10
    return {
        "version": API_VERSION,
        "features": features,
        "limits": {"rate_limit_rps": rps},
    }


@v1.get("/whoami")
async def whoami(role: Literal["user", "admin"] = Depends(auth_service._require_auth())):
    # Return the effective role for the caller's token
    return {"role": role}


admin = APIRouter(prefix="/ui/v1/admin", dependencies=[Depends(auth_service._require_auth("admin"))])


@admin.get("/ping")
async def admin_ping():
    return {"ok": True}


"""
Routers are included after all endpoints are defined below.
This ensures endpoints added later (e.g., /ui/v1/requests) are registered.
"""


# In production, expose Swagger UI only to admins
if os.getenv("ENVIRONMENT", "development").strip().lower() == "production":

    @app.get("/ui/v1/docs", dependencies=[Depends(auth_service._require_auth("admin"))])
    async def _swagger_ui_admin_only():
        return get_swagger_ui_html(
            openapi_url="/ui/v1/openapi.json",
            title="AI Proxy Logs UI API - Docs",
        )


# ---- Requests listing (Stage U3) ----
# Requests endpoints moved to `ai_proxy_ui.routers.requests` as part of Stage 6 refactor.
# See `ai_proxy_ui/routers/requests.py` for implementations of `/ui/v1/requests` and
# `/ui/v1/requests/{request_id}`.


# ---- Request details (Stage U4) ----
# Request details implementation moved to `ai_proxy_ui.routers.requests` during refactor.
# The legacy implementations were removed from `ai_proxy_ui.main` to avoid duplicate
# routing and to centralize all request-related logic in the `routers.requests` module.
# Use `ai_proxy_ui.routers.requests` for request details and listing.


# Include routers after all route declarations
app.include_router(requests_router.router)
app.include_router(v1)
app.include_router(admin)
