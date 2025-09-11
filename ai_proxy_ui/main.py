from fastapi import FastAPI, APIRouter, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.openapi.docs import get_swagger_ui_html
import os
import time
import uuid
from typing import Literal


def _get_allowed_origins() -> list[str]:
    origins = os.getenv("LOGUI_ALLOWED_ORIGINS", "*")
    # CSV to list, trim whitespace
    parts = [p.strip() for p in origins.split(",") if p.strip()]
    return parts if parts else ["*"]


def _get_bool_env(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _get_csv_env(name: str) -> set[str]:
    raw = os.getenv(name, "")
    return {item.strip() for item in raw.split(",") if item.strip()}


API_VERSION = "ui.v1"

ENVIRONMENT = os.getenv("ENVIRONMENT", "development").strip().lower()

app = FastAPI(
    title="AI Proxy Logs UI API",
    openapi_url="/ui/v1/openapi.json",
    docs_url=("/ui/v1/docs" if ENVIRONMENT != "production" else None),
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


# Simple per-key rate limiter (fixed window per second)
_rate_limit_rps_default = 10
_rate_limit_buckets: dict[str, tuple[int, int]] = {}
_rate_limit_cached_rps: int | None = None
# token -> (window_epoch_second, count)


def _check_rate_limit(token: str):
    global _rate_limit_cached_rps
    try:
        rps = int(os.getenv("LOGUI_RATE_LIMIT_RPS", str(_rate_limit_rps_default)))
    except ValueError:
        rps = _rate_limit_rps_default

    # Reset buckets if RPS setting changed between requests/tests
    if _rate_limit_cached_rps is None or _rate_limit_cached_rps != rps:
        _rate_limit_buckets.clear()
        _rate_limit_cached_rps = rps
    now_sec = int(time.time())
    window, count = _rate_limit_buckets.get(token, (now_sec, 0))
    if window != now_sec:
        window, count = now_sec, 0
    count += 1
    _rate_limit_buckets[token] = (window, count)
    if count > rps:
        # Advise client when to retry (next second)
        raise HTTPException(status_code=429, detail="Rate limit exceeded")


def _require_auth(role: Literal["user", "admin"] | None = None):
    user_keys = _get_csv_env("LOGUI_API_KEYS")
    admin_keys = _get_csv_env("LOGUI_ADMIN_API_KEYS")

    async def dependency(request: Request):
        auth_header = request.headers.get("authorization") or request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")

        token = auth_header.split(" ", 1)[1].strip()
        if not token:
            raise HTTPException(status_code=401, detail="Empty token")

        # Rate limit per token
        _check_rate_limit(token)

        effective_role: Literal["admin", "user"] | None = None
        if token in admin_keys:
            effective_role = "admin"
        elif token in user_keys:
            effective_role = "user"

        if effective_role is None:
            raise HTTPException(status_code=401, detail="Invalid API key")

        if role == "admin" and effective_role != "admin":
            raise HTTPException(status_code=403, detail="Admin privileges required")

        # stash role for downstream (optional)
        request.state.role = effective_role
        request.state.token = token
        return effective_role

    return dependency


@app.get("/ui/health")
async def health_legacy():
    return {"status": "ok"}


v1 = APIRouter(prefix="/ui/v1", dependencies=[Depends(_require_auth())])


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


admin = APIRouter(prefix="/ui/v1/admin", dependencies=[Depends(_require_auth("admin"))])


@admin.get("/ping")
async def admin_ping():
    return {"ok": True}


app.include_router(v1)
app.include_router(admin)


# In production, expose Swagger UI only to admins
if ENVIRONMENT == "production":
    @app.get("/ui/v1/docs", dependencies=[Depends(_require_auth("admin"))])
    async def _swagger_ui_admin_only():
        return get_swagger_ui_html(
            openapi_url="/ui/v1/openapi.json",
            title="AI Proxy Logs UI API - Docs",
        )

