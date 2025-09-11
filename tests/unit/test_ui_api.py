import os
from fastapi.testclient import TestClient


def test_health_endpoints_import_and_respond():
    # Ensure wildcard CORS for simplicity
    os.environ["LOGUI_ALLOWED_ORIGINS"] = "*"
    os.environ["LOGUI_API_KEYS"] = "user-key"
    os.environ["LOGUI_ADMIN_API_KEYS"] = "admin-key"

    from ai_proxy_ui.main import app  # import after env set

    client = TestClient(app)

    # Legacy health does not require auth
    r = client.get("/ui/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}
    assert r.headers.get("x-api-version") == "ui.v1"
    assert r.headers.get("x-request-id")

    # v1 health requires auth
    r = client.get("/ui/v1/health")
    assert r.status_code == 401
    body = r.json()
    assert body["code"] == 401

    r = client.get("/ui/v1/health", headers={"Authorization": "Bearer user-key"})
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}
    assert r.headers.get("x-api-version") == "ui.v1"
    assert r.headers.get("x-request-id")


def test_config_endpoint_and_rbac():
    os.environ["LOGUI_API_KEYS"] = "user-key"
    os.environ["LOGUI_ADMIN_API_KEYS"] = "admin-key"
    os.environ["LOGDB_FTS_ENABLED"] = "true"
    os.environ["LOGUI_ENABLE_TEXT_LOGS"] = "false"
    os.environ["LOGUI_RATE_LIMIT_RPS"] = "7"

    from ai_proxy_ui.main import app

    client = TestClient(app)

    # Requires user auth
    r = client.get("/ui/v1/config")
    assert r.status_code == 401

    r = client.get("/ui/v1/config", headers={"Authorization": "Bearer user-key"})
    assert r.status_code == 200
    data = r.json()
    assert data["version"] == "ui.v1"
    assert data["features"]["fts_enabled"] is True
    assert data["features"]["text_logs_enabled"] is False
    assert data["features"]["admin_enabled"] is True
    assert data["limits"]["rate_limit_rps"] == 7

    # Admin route requires admin key
    r = client.get("/ui/v1/admin/ping", headers={"Authorization": "Bearer user-key"})
    assert r.status_code == 403
    r = client.get("/ui/v1/admin/ping", headers={"Authorization": "Bearer admin-key"})
    assert r.status_code == 200
    assert r.json() == {"ok": True}


def test_cors_allows_configured_origin():
    os.environ["LOGUI_ALLOWED_ORIGINS"] = "http://localhost:5173"
    os.environ["LOGUI_API_KEYS"] = "user-key"

    from ai_proxy_ui.main import app

    client = TestClient(app)
    origin = "http://localhost:5173"
    r = client.options(
        "/ui/v1/health",
        headers={
            "Origin": origin,
            "Access-Control-Request-Method": "GET",
            "Authorization": "Bearer user-key",
        },
    )
    # Preflight should succeed and reflect the origin
    assert r.status_code in (200, 204)
    allow_origin = r.headers.get("access-control-allow-origin")
    assert allow_origin == origin or allow_origin == "*"


def test_swagger_ui_gated_in_production_for_admin_only(monkeypatch):
    # Force production environment
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("LOGUI_API_KEYS", "user-key")
    monkeypatch.setenv("LOGUI_ADMIN_API_KEYS", "admin-key")

    # Import app after env set to apply gating
    from importlib import reload
    import ai_proxy_ui.main as main_module
    reload(main_module)
    app = main_module.app
    client = TestClient(app)

    # Unauthenticated should be 401
    r = client.get("/ui/v1/docs")
    assert r.status_code == 401

    # User key should be 403
    r = client.get("/ui/v1/docs", headers={"Authorization": "Bearer user-key"})
    assert r.status_code == 403

    # Admin key should get HTML page
    r = client.get("/ui/v1/docs", headers={"Authorization": "Bearer admin-key"})
    assert r.status_code == 200
    assert "text/html" in r.headers.get("content-type", "")


def test_rate_limit_enforced_per_key():
    os.environ["LOGUI_API_KEYS"] = "user-key"
    os.environ["LOGUI_RATE_LIMIT_RPS"] = "2"

    from ai_proxy_ui.main import app

    client = TestClient(app)
    # First two requests should pass
    for _ in range(2):
        r = client.get("/ui/v1/health", headers={"Authorization": "Bearer user-key"})
        assert r.status_code == 200
    # Third within same second should 429
    r = client.get("/ui/v1/health", headers={"Authorization": "Bearer user-key"})
    assert r.status_code == 429
    body = r.json()
    assert body["code"] == 429


def _make_partition(db_path: str, rows: int, base_ts: int, start_id: int = 0):
    import sqlite3
    import os as _os
    _os.makedirs(_os.path.dirname(db_path), exist_ok=True)
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
                rid = f"t{start_id + i:04d}"
                conn.execute(
                    "INSERT OR IGNORE INTO requests(request_id, server_id, ts, endpoint, model_original, model_mapped, status_code, latency_ms, api_key_hash, request_json, response_json, dialog_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,NULL)",
                    (
                        rid,
                        "srv-1",
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


def test_requests_listing_cross_partitions_and_pagination(tmp_path, monkeypatch):
    # Prepare two daily partitions under logs/db/YYYY/MM
    import datetime as dt
    base_dir = tmp_path / "logs" / "db"
    d1 = dt.date(2025, 9, 9)
    d2 = dt.date(2025, 9, 10)
    p1 = base_dir / f"{d1.year:04d}" / f"{d1.month:02d}" / f"ai_proxy_{d1.strftime('%Y%m%d')}.sqlite3"
    p2 = base_dir / f"{d2.year:04d}" / f"{d2.month:02d}" / f"ai_proxy_{d2.strftime('%Y%m%d')}.sqlite3"
    # Insert 3 rows on day1 and 2 rows on day2 with increasing timestamps
    base_ts1 = int(dt.datetime(d1.year, d1.month, d1.day, 12, 0).timestamp())
    base_ts2 = int(dt.datetime(d2.year, d2.month, d2.day, 12, 0).timestamp())
    _make_partition(str(p1), rows=3, base_ts=base_ts1, start_id=0)
    _make_partition(str(p2), rows=2, base_ts=base_ts2, start_id=100)

    # Configure API env
    monkeypatch.setenv("LOGUI_API_KEYS", "user-key")
    monkeypatch.setenv("LOGUI_DB_ROOT", str(base_dir))

    from ai_proxy_ui.main import app
    client = TestClient(app)

    # First page (limit 3) over both days should return most recent rows from day2 first
    r = client.get(
        "/ui/v1/requests",
        params={"since": str(d1), "to": str(d2), "limit": 3},
        headers={"Authorization": "Bearer user-key"},
    )
    assert r.status_code == 200
    data = r.json()
    assert len(data["items"]) == 3
    assert data["nextCursor"]
    # Ensure ordering desc by ts then request_id
    ts_list = [it["ts"] for it in data["items"]]
    assert ts_list == sorted(ts_list, reverse=True)

    # Next page
    r2 = client.get(
        "/ui/v1/requests",
        params={"since": str(d1), "to": str(d2), "limit": 3, "cursor": data["nextCursor"]},
        headers={"Authorization": "Bearer user-key"},
    )
    assert r2.status_code == 200
    data2 = r2.json()
    # Remaining 2 rows
    assert len(data2["items"]) == 2
    # No further pages
    assert data2["nextCursor"] is None


