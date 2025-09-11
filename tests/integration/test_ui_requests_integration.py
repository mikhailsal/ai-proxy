import os
import sqlite3
import datetime as dt
from fastapi.testclient import TestClient


def _make_partition(db_path: str, rows: int, base_ts: int, start_id: int = 0):
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(
            """
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS requests (
              request_id TEXT PRIMARY KEY,
              server_id TEXT NOT NULL,
              ts INTEGER NOT NULL,
              endpoint TEXT NOT NULL,
              model_original TEXT,
              model_mapped TEXT,
              status_code INTEGER,
              latency_ms REAL,
              api_key_hash TEXT,
              request_json TEXT NOT NULL,
              response_json TEXT NOT NULL,
              dialog_id TEXT
            );
            """
        )
        with conn:
            for i in range(rows):
                rid = f"int{start_id + i:04d}"
                conn.execute(
                    "INSERT OR IGNORE INTO requests(request_id, server_id, ts, endpoint, model_original, model_mapped, status_code, latency_ms, api_key_hash, request_json, response_json, dialog_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,NULL)",
                    (
                        rid,
                        "srv-int",
                        base_ts + i,
                        "/v1/chat/completions",
                        "m",
                        "m",
                        200,
                        12.5,
                        "k",
                        "{}",
                        "{}",
                    ),
                )
    finally:
        conn.close()


def test_requests_cross_two_days_counts_and_pagination(tmp_path, monkeypatch):
    # Prepare two daily partitions under logs/db/YYYY/MM
    base_dir = tmp_path / "logs" / "db"
    day1 = dt.date(2025, 9, 9)
    day2 = dt.date(2025, 9, 10)
    p1 = base_dir / f"{day1.year:04d}" / f"{day1.month:02d}" / f"ai_proxy_{day1.strftime('%Y%m%d')}.sqlite3"
    p2 = base_dir / f"{day2.year:04d}" / f"{day2.month:02d}" / f"ai_proxy_{day2.strftime('%Y%m%d')}.sqlite3"

    base_ts1 = int(dt.datetime(day1.year, day1.month, day1.day, 12, 0).timestamp())
    base_ts2 = int(dt.datetime(day2.year, day2.month, day2.day, 12, 0).timestamp())

    # 4 rows on day1, 3 rows on day2
    _make_partition(str(p1), rows=4, base_ts=base_ts1, start_id=0)
    _make_partition(str(p2), rows=3, base_ts=base_ts2, start_id=100)

    total_expected = 7

    # Configure API env
    monkeypatch.setenv("LOGUI_API_KEYS", "user-int-key")
    monkeypatch.setenv("LOGUI_DB_ROOT", str(base_dir))

    from ai_proxy_ui.main import app

    client = TestClient(app)

    # Page through with small limit to exercise cursor across day boundary
    collected = []
    next_cursor = None
    page_limit = 2
    for _ in range(10):  # safety bound
        params = {
            "since": str(day1),
            "to": str(day2),
            "limit": page_limit,
        }
        if next_cursor:
            params["cursor"] = next_cursor
        r = client.get("/ui/v1/requests", params=params, headers={"Authorization": "Bearer user-int-key"})
        assert r.status_code == 200
        data = r.json()
        collected.extend(data["items"])
        next_cursor = data["nextCursor"]
        # Ensure ordering within page is descending by ts
        page_ts = [it["ts"] for it in data["items"]]
        assert page_ts == sorted(page_ts, reverse=True)
        if not next_cursor:
            break

    # Verify total count across pages matches expected
    assert len(collected) == total_expected


