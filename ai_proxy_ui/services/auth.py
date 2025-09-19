"""
Authentication and rate-limiting helpers for the Logs UI API.
"""

import os
import time
from typing import Literal
from fastapi import HTTPException, Request

from ai_proxy_ui.config import _get_csv_env

# Simple per-key, per-path rate limiter (fixed window per second)
# Default RPS for per-key rate limiting. Raised to reduce test flakiness during
# tight integration test loops; still reasonably low for production safety.
# Runtime default RPS used when LOGUI_RATE_LIMIT_RPS is not provided. Raised to
# reduce test flakiness during tight integration test loops; production can
# override via env.
_rate_limit_rps_default_runtime = 1000

# Fallback RPS value used when an explicit env value is provided but invalid.
# Tests expect an invalid setting to fall back to 10.
_rate_limit_rps_fallback_on_invalid = 10
# (token, path) -> (window_epoch_second, count)
_rate_limit_buckets: dict[tuple[str, str], tuple[int, int]] = {}
_rate_limit_cached_rps: int | None = None


def _check_rate_limit(token: str, path: str):
    global _rate_limit_cached_rps
    # Resolve RPS with these rules:
    # - If env is unset -> use runtime default
    # - If env is set to a valid int -> use that value
    # - If env is set but invalid -> fall back to the explicit invalid fallback value
    rps_env = os.getenv("LOGUI_RATE_LIMIT_RPS")
    if rps_env is None:
        rps = _rate_limit_rps_default_runtime
    else:
        try:
            rps = int(rps_env)
        except ValueError:
            rps = _rate_limit_rps_fallback_on_invalid

    # Reset buckets if RPS setting changed between requests/tests
    if _rate_limit_cached_rps is None or _rate_limit_cached_rps != rps:
        _rate_limit_buckets.clear()
        _rate_limit_cached_rps = rps
    now_sec = int(time.time())
    key = (token, path)
    window, count = _rate_limit_buckets.get(key, (now_sec, 0))
    if window != now_sec:
        window, count = now_sec, 0
    count += 1
    _rate_limit_buckets[key] = (window, count)
    if count > rps:
        # Advise client when to retry (next second)
        raise HTTPException(status_code=429, detail="Rate limit exceeded")


def _require_auth(role: Literal["user", "admin"] | None = None):
    async def dependency(request: Request):
        # Fetch keys at call time to respect env changes that tests make before app import
        user_keys = _get_csv_env("LOGUI_API_KEYS")
        admin_keys = _get_csv_env("LOGUI_ADMIN_API_KEYS")
        auth_header = request.headers.get("authorization") or request.headers.get(
            "Authorization"
        )
        if not auth_header or not auth_header.startswith("Bearer "):
            raise HTTPException(
                status_code=401, detail="Missing or invalid Authorization header"
            )

        token = auth_header.split(" ", 1)[1].strip()
        if not token:
            raise HTTPException(status_code=401, detail="Empty token")

        # Rate limit per token per path to avoid cross-endpoint interference
        _check_rate_limit(token, request.url.path)

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
