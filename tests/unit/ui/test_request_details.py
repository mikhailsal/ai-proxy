# New file with request details tests
import os
import datetime as dt
from fastapi.testclient import TestClient


def test_request_details_endpoint_returns_full_payload(tmp_path, monkeypatch):
    base_dir = tmp_path / "logs" / "db"
    d = dt.date(2025, 9, 10)
    p = (
        base_dir
        / f"{d.year:04d}"
        / f"{d.month:02d}"
        / f"ai_proxy_{d.strftime('%Y%m%d')}.sqlite3"
    )

    os.makedirs(os.path.dirname(p), exist_ok=True)
    import sqlite3 as _sqlite

    conn = _sqlite.connect(str(p))
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
            conn.execute(
                "INSERT OR IGNORE INTO requests(request_id, server_id, ts, endpoint, model_original, model_mapped, status_code, latency_ms, api_key_hash, request_json, response_json, dialog_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,NULL)",
                (
                    "rid-1",
                    "srv-1",
                    int(dt.datetime(d.year, d.month, d.day, 12, 0).timestamp()),
                    "/v1/chat/completions",
                    "m",
                    "m",
                    200,
                    33.7,
                    "k",
                    '{"messages":[{"role":"user","content":"hi"}] }',
                    '{"choices":[{"message":{"role":"assistant","content":"hello"}}] }',
                ),
            )
    finally:
        conn.close()

    monkeypatch.setenv("LOGUI_API_KEYS", "user-key")
    monkeypatch.setenv("LOGUI_DB_ROOT", str(base_dir))

    from ai_proxy_ui.main import app

    client = TestClient(app)

    r = client.get(
        "/ui/v1/requests/rid-1", headers={"Authorization": "Bearer user-key"}
    )
    assert r.status_code == 200
    data = r.json()
    assert data["request_id"] == "rid-1"
    assert data["endpoint"] == "/v1/chat/completions"
    assert data["status_code"] == 200
    assert isinstance(data["request_json"], dict)
    assert isinstance(data["response_json"], dict)

    r2 = client.get(
        "/ui/v1/requests/unknown", headers={"Authorization": "Bearer user-key"}
    )
    assert r2.status_code == 404
