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


@v1.get("/whoami")
async def whoami(role: Literal["user", "admin"] = Depends(_require_auth())):
    # Return the effective role for the caller's token
    return {"role": role}


admin = APIRouter(prefix="/ui/v1/admin", dependencies=[Depends(_require_auth("admin"))])


@admin.get("/ping")
async def admin_ping():
    return {"ok": True}


"""
Routers are included after all endpoints are defined below.
This ensures endpoints added later (e.g., /ui/v1/requests) are registered.
"""


# In production, expose Swagger UI only to admins
if ENVIRONMENT == "production":
    @app.get("/ui/v1/docs", dependencies=[Depends(_require_auth("admin"))])
    async def _swagger_ui_admin_only():
        return get_swagger_ui_html(
            openapi_url="/ui/v1/openapi.json",
            title="AI Proxy Logs UI API - Docs",
        )


# ---- Requests listing (Stage U3) ----

def _parse_date_param(value: Optional[str], default: Optional[_dt.date] = None) -> _dt.date:
    if not value:
        if default is None:
            raise HTTPException(status_code=400, detail="Missing date parameter")
        return default
    try:
        return _dt.date.fromisoformat(value)
    except Exception:
        raise HTTPException(status_code=400, detail=f"Invalid date: {value}")


def _epoch_range_for_dates(since: _dt.date, to: _dt.date) -> Tuple[int, int]:
    start = int(_dt.datetime.combine(since, _dt.time.min).timestamp())
    end = int(_dt.datetime.combine(to, _dt.time.max).timestamp())
    return start, end


def _iter_partition_paths(base_dir: str, since: _dt.date, to: _dt.date) -> List[str]:
    # Lazy import to avoid coupling at module import time
    from ai_proxy.logdb.partitioning import compute_partition_path

    # Support daily and weekly via compute_partition_path; de-duplicate paths
    current = since
    paths: List[str] = []
    seen: set[str] = set()
    # Iterate by 1 day increments to cover both daily and weekly groupings
    while current <= to:
        p = compute_partition_path(base_dir, current)
        if p not in seen and os.path.isfile(p):
            paths.append(p)
            seen.add(p)
        current += _dt.timedelta(days=1)
    return paths


def _encode_cursor(ts: int, request_id: str) -> str:
    raw = f"{ts}|{request_id}".encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii")


def _decode_cursor(cursor: str) -> Tuple[int, str]:
    try:
        raw = base64.urlsafe_b64decode(cursor.encode("ascii")).decode("utf-8")
        ts_str, rid = raw.split("|", 1)
        return int(ts_str), rid
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid cursor")


@v1.get("/requests")
async def list_requests(
    since: Optional[str] = Query(None, description="ISO date YYYY-MM-DD inclusive"),
    to: Optional[str] = Query(None, description="ISO date YYYY-MM-DD inclusive"),
    limit: int = Query(50, ge=1, le=500),
    cursor: Optional[str] = Query(None),
):
    base_dir = os.getenv("LOGUI_DB_ROOT", os.path.join(".", "logs", "db"))

    today = _dt.date.today()
    start_date = _parse_date_param(since, default=today)
    end_date = _parse_date_param(to, default=today)
    if end_date < start_date:
        raise HTTPException(status_code=400, detail="'to' date must be on/after 'since'")

    # Resolve partitions
    db_files = _iter_partition_paths(base_dir, start_date, end_date)
    if not db_files:
        return {"items": [], "nextCursor": None}

    # Build query
    ts_start, ts_end = _epoch_range_for_dates(start_date, end_date)
    where_clauses = ["ts >= ?", "ts <= ?"]
    params: List[object] = [ts_start, ts_end]
    if cursor:
        c_ts, c_rid = _decode_cursor(cursor)
        # For DESC order, fetch rows strictly less than the cursor tuple
        where_clauses.append("(ts < ?) OR (ts = ? AND request_id < ?)")
        params.extend([c_ts, c_ts, c_rid])

    union_sql_parts: List[str] = []
    for i in range(len(db_files)):
        alias = f"db{i}"
        union_sql_parts.append(
            f"SELECT request_id, ts, endpoint, COALESCE(model_mapped, model_original) AS model, status_code, latency_ms FROM {alias}.requests"
        )
    union_sql = " UNION ALL ".join(union_sql_parts)
    sql = (
        "WITH allreq AS ("
        + union_sql
        + ") SELECT request_id, ts, endpoint, model, status_code, latency_ms FROM allreq WHERE "
        + " AND ".join(where_clauses)
        + " ORDER BY ts DESC, request_id DESC LIMIT ?"
    )
    params.append(limit + 1)  # overfetch to determine next cursor

    # Query via single in-memory connection, attach partitions as read-only immutable
    conn = sqlite3.connect("file::memory:?cache=shared", uri=True)
    try:
        conn.execute("PRAGMA query_only=ON;")
        for i, path in enumerate(db_files):
            alias = f"db{i}"
            uri_path = f"file:{os.path.abspath(path)}?mode=ro&immutable=1"
            conn.execute("ATTACH DATABASE ? AS "+alias, (uri_path,))

        cur = conn.execute(sql, params)
        rows = cur.fetchall()
        # Build items and next cursor
        items = [
            {
                "request_id": r[0],
                "ts": int(r[1]),
                "endpoint": r[2],
                "model": r[3],
                "status_code": int(r[4]) if r[4] is not None else None,
                "latency_ms": float(r[5]) if r[5] is not None else None,
            }
            for r in rows[:limit]
        ]
        next_cursor = None
        if len(rows) > limit:
            last = rows[limit - 1]
            next_cursor = _encode_cursor(int(last[1]), str(last[0]))
        return {"items": items, "nextCursor": next_cursor}
    finally:
        conn.close()


# ---- Request details (Stage U4) ----

def _iter_all_partitions(base_dir: str) -> List[str]:
    paths: List[str] = []
    for root, _dirs, files in os.walk(base_dir):
        for fname in files:
            if not fname.endswith(".sqlite3"):
                continue
            # basic pattern guard: ai_proxy_YYYYMMDD.sqlite3
            if not fname.startswith("ai_proxy_"):
                continue
            paths.append(os.path.join(root, fname))
    # stable order to improve determinism
    paths.sort()
    return paths


@v1.get("/requests/{request_id}")
async def get_request_details(request_id: str):
    base_dir = os.getenv("LOGUI_DB_ROOT", os.path.join(".", "logs", "db"))

    db_files = _iter_all_partitions(base_dir)
    if not db_files:
        raise HTTPException(status_code=404, detail="Request not found")

    # Build union query to fetch one row by request_id
    select_cols = (
        "request_id, server_id, ts, endpoint, model_original, model_mapped, "
        "status_code, latency_ms, api_key_hash, request_json, response_json, dialog_id"
    )
    union_sql_parts: List[str] = []
    for i in range(len(db_files)):
        alias = f"db{i}"
        union_sql_parts.append(f"SELECT {select_cols} FROM {alias}.requests WHERE request_id = ?")
    union_sql = " UNION ALL ".join(union_sql_parts)
    sql = f"SELECT {select_cols} FROM (" + union_sql + ") LIMIT 1"

    conn = sqlite3.connect("file::memory:?cache=shared", uri=True)
    try:
        conn.execute("PRAGMA query_only=ON;")
        for i, path in enumerate(db_files):
            alias = f"db{i}"
            uri_path = f"file:{os.path.abspath(path)}?mode=ro&immutable=1"
            conn.execute("ATTACH DATABASE ? AS "+alias, (uri_path,))

        # Prepare params repeated for each union branch
        params: List[object] = [request_id] * len(db_files)
        cur = conn.execute(sql, params)
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Request not found")

        def _safe_json_loads(text: Optional[str]):
            if text is None:
                return None
            try:
                return json.loads(text)
            except Exception:
                return text  # return raw text if not valid JSON

        body = {
            "request_id": row[0],
            "server_id": row[1],
            "ts": int(row[2]),
            "endpoint": row[3],
            "model_original": row[4],
            "model_mapped": row[5],
            "status_code": int(row[6]) if row[6] is not None else None,
            "latency_ms": float(row[7]) if row[7] is not None else None,
            "api_key_hash": row[8],
            "request_json": _safe_json_loads(row[9]),
            "response_json": _safe_json_loads(row[10]),
            "dialog_id": row[11],
        }
        return body
    finally:
        conn.close()


# Include routers after all route declarations
app.include_router(v1)
app.include_router(admin)

