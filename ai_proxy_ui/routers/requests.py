"""
Requests router for Logs UI API split out from `ai_proxy_ui/main.py` during refactor Stage 6.
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from typing import Optional, List, Tuple
import os
import datetime as _dt
import base64
import sqlite3
import json

from ai_proxy_ui.services import auth as auth_service

router = APIRouter(
    prefix="/ui/v1", dependencies=[Depends(auth_service._require_auth())]
)


def _parse_date_param(
    value: Optional[str], default: Optional[_dt.date] = None
) -> _dt.date:
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
    from ai_proxy.logdb.partitioning import compute_partition_path

    current = since
    paths: List[str] = []
    seen: set[str] = set()
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


@router.get("/requests")
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
        raise HTTPException(
            status_code=400, detail="'to' date must be on/after 'since'"
        )

    db_files = _iter_partition_paths(base_dir, start_date, end_date)
    if not db_files:
        return {"items": [], "nextCursor": None}

    ts_start, ts_end = _epoch_range_for_dates(start_date, end_date)
    where_clauses = ["ts >= ?", "ts <= ?"]
    params: List[object] = [ts_start, ts_end]
    if cursor:
        c_ts, c_rid = _decode_cursor(cursor)
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
    params.append(limit + 1)

    conn = sqlite3.connect("file::memory:?cache=shared", uri=True)
    try:
        conn.execute("PRAGMA query_only=ON;")
        for i, path in enumerate(db_files):
            alias = f"db{i}"
            uri_path = f"file:{os.path.abspath(path)}?mode=ro&immutable=1"
            conn.execute("ATTACH DATABASE ? AS " + alias, (uri_path,))

        cur = conn.execute(sql, params)
        rows = cur.fetchall()
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


@router.get("/requests/{request_id}")
async def get_request_details(request_id: str):
    base_dir = os.getenv("LOGUI_DB_ROOT", os.path.join(".", "logs", "db"))

    db_files = _iter_all_partitions(base_dir)
    if not db_files:
        raise HTTPException(status_code=404, detail="Request not found")

    select_cols = (
        "request_id, server_id, ts, endpoint, model_original, model_mapped, "
        "status_code, latency_ms, api_key_hash, request_json, response_json, dialog_id"
    )
    union_sql_parts: List[str] = []
    for i in range(len(db_files)):
        alias = f"db{i}"
        union_sql_parts.append(
            f"SELECT {select_cols} FROM {alias}.requests WHERE request_id = ?"
        )
    union_sql = " UNION ALL ".join(union_sql_parts)
    sql = f"SELECT {select_cols} FROM (" + union_sql + ") LIMIT 1"

    conn = sqlite3.connect("file::memory:?cache=shared", uri=True)
    try:
        conn.execute("PRAGMA query_only=ON;")
        for i, path in enumerate(db_files):
            alias = f"db{i}"
            uri_path = f"file:{os.path.abspath(path)}?mode=ro&immutable=1"
            conn.execute("ATTACH DATABASE ? AS " + alias, (uri_path,))

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
                return text

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


def _iter_all_partitions(base_dir: str) -> List[str]:
    paths: List[str] = []
    for root, _dirs, files in os.walk(base_dir):
        for fname in files:
            if not fname.endswith(".sqlite3"):
                continue
            if not fname.startswith("ai_proxy_"):
                continue
            paths.append(os.path.join(root, fname))
    paths.sort()
    return paths
