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

    db_files = _iter_range_with_merged(base_dir, start_date, end_date)
    if not db_files:
        return {"items": [], "nextCursor": None}

    ts_start, ts_end = _epoch_range_for_dates(start_date, end_date)
    where_clauses = ["ts >= ?", "ts <= ?"]
    params: List[object] = [ts_start, ts_end]
    if cursor:
        c_ts, c_rid = _decode_cursor(cursor)
        where_clauses.append("(ts < ?) OR (ts = ? AND request_id < ?)")
        params.extend([c_ts, c_ts, c_rid])

    # Attach-free querying: read each DB independently and merge results
    # Fetch limit+1 from each partition to correctly detect existence of next page
    per_db_limit = limit + 1
    cols = "request_id, ts, endpoint, COALESCE(model_mapped, model_original) AS model, status_code, latency_ms"
    where_sql = " AND ".join(where_clauses)
    sql = (
        f"SELECT {cols} FROM requests WHERE "
        + where_sql
        + " ORDER BY ts DESC, request_id DESC LIMIT ?"
    )

    aggregate: List[tuple] = []
    for path in db_files:
        uri = f"file:{os.path.abspath(path)}?mode=ro&immutable=1"
        try:
            conn = sqlite3.connect(uri, uri=True)
            try:
                cur = conn.execute(sql, list(params) + [per_db_limit])
                aggregate.extend(cur.fetchall())
            finally:
                conn.close()
        except sqlite3.OperationalError:
            continue

    if not aggregate:
        return {"items": [], "nextCursor": None}

    aggregate.sort(key=lambda r: (int(r[1]), str(r[0])), reverse=True)
    rows = aggregate[: limit + 1]
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


@router.get("/requests/{request_id}")
async def get_request_details(request_id: str):
    base_dir = os.getenv("LOGUI_DB_ROOT", os.path.join(".", "logs", "db"))

    # Search newest-first across available merged and daily partitions
    today = _dt.date.today()
    oldest = _dt.date(1970, 1, 1)
    db_files = _iter_range_with_merged(base_dir, oldest, today)
    if not db_files:
        raise HTTPException(status_code=404, detail="Request not found")

    select_cols = (
        "request_id, server_id, ts, endpoint, model_original, model_mapped, "
        "status_code, latency_ms, api_key_hash, request_json, response_json, dialog_id"
    )
    sql = f"SELECT {select_cols} FROM requests WHERE request_id = ? LIMIT 1"

    for path in db_files:
        uri = f"file:{os.path.abspath(path)}?mode=ro&immutable=1"
        try:
            conn = sqlite3.connect(uri, uri=True)
            try:
                cur = conn.execute(sql, (request_id,))
                row = cur.fetchone()
                if row:

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
        except sqlite3.OperationalError:
            continue

    raise HTTPException(status_code=404, detail="Request not found")


def _iter_range_with_merged(base_dir: str, since: _dt.date, to: _dt.date) -> List[str]:
    """Resolve DB files for [since, to] preferring merged monthly/weekly DBs when present,
    and falling back to daily partitions for partial edges or when merged files are missing.
    Newest-first ordering to help short-circuit scans.
    """
    from ai_proxy.logdb.partitioning import compute_partition_path

    # Collect daily partitions in range
    day_to_path: dict[_dt.date, str] = {}
    cur = since
    while cur <= to:
        p = compute_partition_path(base_dir, cur)
        if os.path.isfile(p):
            day_to_path[cur] = p
        cur += _dt.timedelta(days=1)

    covered_days: set[_dt.date] = set()
    selected: List[str] = []

    # Monthly merged preference (new aggregate layout under base/YYYY/MNN/ai_proxy_YYYYMM.sqlite3)
    m_cursor = _dt.date(since.year, since.month, 1)
    last_m = _dt.date(to.year, to.month, 1)
    months: List[tuple[int, int]] = []
    while m_cursor <= last_m:
        months.append((m_cursor.year, m_cursor.month))
        if m_cursor.month == 12:
            m_cursor = _dt.date(m_cursor.year + 1, 1, 1)
        else:
            m_cursor = _dt.date(m_cursor.year, m_cursor.month + 1, 1)
    # newest first
    for y, m in sorted(months, reverse=True):
        # compute month range
        start_m = _dt.date(y, m, 1)
        if m == 12:
            end_m = _dt.date(y, 12, 31)
        else:
            end_m = _dt.date(y, m + 1, 1) - _dt.timedelta(days=1)
        # Only if month fully inside [since, to]
        if not (start_m >= since and end_m <= to):
            continue
        # Prefer new merged monthly aggregate path
        try:
            from ai_proxy.logdb.partitioning import compute_monthly_aggregate_path

            merged_path = compute_monthly_aggregate_path(base_dir, start_m)
        except Exception:
            # Fallback to legacy monthly path if helper unavailable
            merged_path = os.path.join(base_dir, "monthly", f"{y:04d}-{m:02d}.sqlite3")
        if os.path.isfile(merged_path):
            selected.append(merged_path)
            d = start_m
            while d <= end_m:
                if d in day_to_path:
                    covered_days.add(d)
                d += _dt.timedelta(days=1)

    # Weekly merged preference (ISO weeks) using new aggregate layout base/YYYY/WNN/ai_proxy_YYYYWNN.sqlite3

    # Iterate weeks spanned by [since, to]
    def week_start_end(d: _dt.date) -> tuple[_dt.date, _dt.date, tuple[int, int]]:
        iso_year, iso_week, iso_weekday = d.isocalendar()
        # Monday=1 ... Sunday=7; compute Monday as start
        start = d - _dt.timedelta(days=iso_weekday - 1)
        end = start + _dt.timedelta(days=6)
        return start, end, (iso_year, iso_week)

    # Build unique weeks inside range
    weeks: List[tuple[int, int]] = []
    seen_weeks: set[tuple[int, int]] = set()
    c = since
    while c <= to:
        _ws, _we, key = week_start_end(c)
        if key not in seen_weeks:
            seen_weeks.add(key)
            weeks.append(key)
        c += _dt.timedelta(days=1)
    # newest first by iso-year-week
    for wy, ww in sorted(weeks, reverse=True):
        # compute week start/end from Monday of given iso-year/week
        jan4 = _dt.date(wy, 1, 4)
        jan4_iso_year, jan4_week, jan4_wd = jan4.isocalendar()
        week1_monday = jan4 - _dt.timedelta(days=jan4_wd - 1)
        start = week1_monday + _dt.timedelta(days=(ww - 1) * 7)
        end = start + _dt.timedelta(days=6)
        # Only fully inside [since, to] and not already covered by monthly
        if not (start >= since and end <= to):
            continue
        try:
            from ai_proxy.logdb.partitioning import compute_weekly_path

            merged_path = compute_weekly_path(base_dir, start)
        except Exception:
            merged_path = os.path.join(
                base_dir, "weekly", f"{wy:04d}-W{ww:02d}.sqlite3"
            )
        if os.path.isfile(merged_path):
            selected.append(merged_path)
            d = start
            while d <= end:
                if d in day_to_path:
                    covered_days.add(d)
                d += _dt.timedelta(days=1)

    # Remaining daily partitions, newest first
    for d in sorted(day_to_path.keys(), reverse=True):
        if d in covered_days:
            continue
        selected.append(day_to_path[d])

    return selected


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
