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


def test_whoami_returns_effective_role(monkeypatch):
    monkeypatch.setenv("LOGUI_API_KEYS", "user-key")
    monkeypatch.setenv("LOGUI_ADMIN_API_KEYS", "admin-key")

    from ai_proxy_ui.main import app

    client = TestClient(app)
    # user token → user
    r_user = client.get("/ui/v1/whoami", headers={"Authorization": "Bearer user-key"})
    assert r_user.status_code == 200
    assert r_user.json()["role"] == "user"
    # admin token → admin
    r_admin = client.get("/ui/v1/whoami", headers={"Authorization": "Bearer admin-key"})
    assert r_admin.status_code == 200
    assert r_admin.json()["role"] == "admin"
    # invalid → 401
    r_bad = client.get("/ui/v1/whoami", headers={"Authorization": "Bearer bad"})
    assert r_bad.status_code == 401


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
    p1 = (
        base_dir
        / f"{d1.year:04d}"
        / f"{d1.month:02d}"
        / f"ai_proxy_{d1.strftime('%Y%m%d')}.sqlite3"
    )
    p2 = (
        base_dir
        / f"{d2.year:04d}"
        / f"{d2.month:02d}"
        / f"ai_proxy_{d2.strftime('%Y%m%d')}.sqlite3"
    )
    # Insert 3 rows on day1 and 2 rows on day2 with increasing timestamps
    base_ts1 = int(dt.datetime(d1.year, d1.month, d1.day, 12, 0).timestamp())
    base_ts2 = int(dt.datetime(d2.year, d2.month, d2.day, 12, 0).timestamp())
    _make_partition(str(p1), rows=3, base_ts=base_ts1, start_id=0)
    _make_partition(str(p2), rows=2, base_ts=base_ts2, start_id=100)

    # Configure API env
    monkeypatch.setenv("LOGUI_API_KEYS", "user-key")
    # Avoid cross-test rate limit flakiness
    monkeypatch.setenv("LOGUI_RATE_LIMIT_RPS", "1000")
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
        params={
            "since": str(d1),
            "to": str(d2),
            "limit": 3,
            "cursor": data["nextCursor"],
        },
        headers={"Authorization": "Bearer user-key"},
    )
    assert r2.status_code == 200
    data2 = r2.json()
    # Remaining 2 rows
    assert len(data2["items"]) == 2
    # No further pages
    assert data2["nextCursor"] is None


def test_request_details_endpoint_returns_full_payload(tmp_path, monkeypatch):
    import datetime as dt

    base_dir = tmp_path / "logs" / "db"
    d = dt.date(2025, 9, 10)
    p = (
        base_dir
        / f"{d.year:04d}"
        / f"{d.month:02d}"
        / f"ai_proxy_{d.strftime('%Y%m%d')}.sqlite3"
    )

    # Create one row with JSON payloads
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
                    '{"messages":[{"role":"user","content":"hi"}]}',
                    '{"choices":[{"message":{"role":"assistant","content":"hello"}}]}',
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
    # not found case
    r2 = client.get(
        "/ui/v1/requests/unknown", headers={"Authorization": "Bearer user-key"}
    )
    assert r2.status_code == 404

# New tests for coverage improvement

def test_auth_empty_token_raises_401(monkeypatch):
    monkeypatch.setenv("LOGUI_API_KEYS", "user-key")
    from ai_proxy_ui.main import app
    client = TestClient(app)
    r = client.get("/ui/v1/health", headers={"Authorization": "Bearer "})
    assert r.status_code == 401
    body = r.json()
    assert body["message"] == "Empty token"

def test_list_requests_invalid_dates(monkeypatch):
    monkeypatch.setenv("LOGUI_API_KEYS", "user-key")
    from ai_proxy_ui.main import app
    client = TestClient(app)
    # Invalid format
    r = client.get("/ui/v1/requests", params={"since": "invalid"}, headers={"Authorization": "Bearer user-key"})
    assert r.status_code == 400
    assert "Invalid date" in r.json()["message"]
    # to before since
    r = client.get("/ui/v1/requests", params={"since": "2025-09-10", "to": "2025-09-09"}, headers={"Authorization": "Bearer user-key"})
    assert r.status_code == 400
    assert "to' date must be on/after 'since" in r.json()["message"]

def test_list_requests_no_partitions_returns_empty(monkeypatch, tmp_path):
    monkeypatch.setenv("LOGUI_API_KEYS", "user-key")
    monkeypatch.setenv("LOGUI_RATE_LIMIT_RPS", "1000")
    monkeypatch.setenv("LOGUI_DB_ROOT", str(tmp_path / "empty_db"))
    from ai_proxy_ui.main import app
    client = TestClient(app)
    r = client.get("/ui/v1/requests", params={"since": "2025-09-10", "to": "2025-09-10"}, headers={"Authorization": "Bearer user-key"})
    assert r.status_code == 200
    data = r.json()
    assert data["items"] == []
    assert data["nextCursor"] is None

def test_list_requests_invalid_cursor(tmp_path, monkeypatch):
    # Set up a minimal database so db_files is not empty
    import datetime as dt
    base_dir = tmp_path / "logs" / "db"
    today = dt.date.today()
    p = (
        base_dir
        / f"{today.year:04d}"
        / f"{today.month:02d}"
        / f"ai_proxy_{today.strftime('%Y%m%d')}.sqlite3"
    )
    _make_partition(str(p), rows=1, base_ts=int(dt.datetime(today.year, today.month, today.day, 12, 0).timestamp()), start_id=0)

    monkeypatch.setenv("LOGUI_API_KEYS", "user-key")
    monkeypatch.setenv("LOGUI_RATE_LIMIT_RPS", "1000")
    monkeypatch.setenv("LOGUI_DB_ROOT", str(base_dir))
    from ai_proxy_ui.main import app
    client = TestClient(app)
    r = client.get("/ui/v1/requests", params={"cursor": "!!!"}, headers={"Authorization": "Bearer user-key"})
    assert r.status_code == 400
    assert "Invalid cursor" in r.json()["message"]

def test_get_request_details_invalid_json_fallback(tmp_path, monkeypatch):
    import datetime as dt
    base_dir = tmp_path / "logs" / "db"
    d = dt.date(2025, 9, 10)
    p = base_dir / f"{d.year:04d}" / f"{d.month:02d}" / f"ai_proxy_{d.strftime('%Y%m%d')}.sqlite3"
    os.makedirs(os.path.dirname(p), exist_ok=True)
    import sqlite3 as _sqlite
    conn = _sqlite.connect(str(p))
    try:
        conn.executescript("""
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
            """)
        with conn:
            conn.execute(
                "INSERT OR IGNORE INTO requests(request_id, server_id, ts, endpoint, model_original, model_mapped, status_code, latency_ms, api_key_hash, request_json, response_json, dialog_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,NULL)",
                (
                    "rid-bad",
                    "srv-1",
                    int(dt.datetime(d.year, d.month, d.day, 12, 0).timestamp()),
                    "/v1/chat/completions",
                    "m",
                    "m",
                    200,
                    33.7,
                    "k",
                    "invalid json",
                    "also invalid",
                ),
            )
    finally:
        conn.close()
    monkeypatch.setenv("LOGUI_API_KEYS", "user-key")
    monkeypatch.setenv("LOGUI_DB_ROOT", str(base_dir))
    from ai_proxy_ui.main import app
    client = TestClient(app)
    r = client.get("/ui/v1/requests/rid-bad", headers={"Authorization": "Bearer user-key"})
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data["request_json"], str)
    assert data["request_json"] == "invalid json"
    assert isinstance(data["response_json"], str)
    assert data["response_json"] == "also invalid"

def test_config_defaults_when_env_unset(monkeypatch):
    monkeypatch.setenv("LOGUI_API_KEYS", "user-key")
    monkeypatch.delenv("LOGDB_FTS_ENABLED", raising=False)
    monkeypatch.delenv("LOGUI_ENABLE_TEXT_LOGS", raising=False)
    monkeypatch.delenv("LOGUI_ADMIN_API_KEYS", raising=False)
    monkeypatch.delenv("LOGUI_RATE_LIMIT_RPS", raising=False)
    from ai_proxy_ui.main import app
    client = TestClient(app)
    r = client.get("/ui/v1/config", headers={"Authorization": "Bearer user-key"})
    assert r.status_code == 200
    data = r.json()
    assert data["features"]["fts_enabled"] is False
    assert data["features"]["text_logs_enabled"] is False
    assert data["features"]["admin_enabled"] is False
    assert data["limits"]["rate_limit_rps"] == 10

# Additional tests for remaining coverage

def test_rate_limit_invalid_rps_falls_back(monkeypatch):
    monkeypatch.setenv("LOGUI_API_KEYS", "user-key")
    monkeypatch.setenv("LOGUI_RATE_LIMIT_RPS", "invalid")
    from ai_proxy_ui.main import app, _rate_limit_buckets
    # Clear any existing rate limit buckets
    _rate_limit_buckets.clear()
    client = TestClient(app)
    # Make requests to trigger the fallback path
    for _ in range(11):  # Default is 10, so 11th should 429
        r = client.get("/ui/v1/health", headers={"Authorization": "Bearer user-key"})
    assert r.status_code == 429

def test_config_invalid_rps_falls_back(monkeypatch):
    monkeypatch.setenv("LOGUI_API_KEYS", "user-key")
    monkeypatch.setenv("LOGUI_RATE_LIMIT_RPS", "invalid")
    from ai_proxy_ui.main import app
    client = TestClient(app)
    r = client.get("/ui/v1/config", headers={"Authorization": "Bearer user-key"})
    assert r.status_code == 200
    assert r.json()["limits"]["rate_limit_rps"] == 10

def test_parse_date_no_value_no_default_raises(monkeypatch):
    # Direct import to test helper
    from ai_proxy_ui.main import _parse_date_param
    import pytest
    with pytest.raises(Exception) as exc:
        _parse_date_param(None, None)
    assert "Missing date parameter" in str(exc.value)

def test_request_details_no_partitions_404(monkeypatch, tmp_path):
    monkeypatch.setenv("LOGUI_API_KEYS", "user-key")
    monkeypatch.setenv("LOGUI_DB_ROOT", str(tmp_path / "empty_db"))
    from ai_proxy_ui.main import app
    client = TestClient(app)
    r = client.get("/ui/v1/requests/some_id", headers={"Authorization": "Bearer user-key"})
    assert r.status_code == 404
    assert "Request not found" in r.json()["message"]

def test_request_details_none_json_returns_none(tmp_path, monkeypatch):
    import datetime as dt
    base_dir = tmp_path / "logs" / "db"
    d = dt.date(2025, 9, 10)
    p = base_dir / f"{d.year:04d}" / f"{d.month:02d}" / f"ai_proxy_{d.strftime('%Y%m%d')}.sqlite3"
    os.makedirs(os.path.dirname(p), exist_ok=True)
    import sqlite3 as _sqlite
    conn = _sqlite.connect(str(p))
    try:
        conn.executescript("""
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
              request_json TEXT,
              response_json TEXT,
              dialog_id TEXT
            );
            """)
        with conn:
            conn.execute(
                "INSERT OR IGNORE INTO requests(request_id, server_id, ts, endpoint, model_original, model_mapped, status_code, latency_ms, api_key_hash, request_json, response_json, dialog_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,NULL)",
                (
                    "rid-none",
                    "srv-1",
                    int(dt.datetime(d.year, d.month, d.day, 12, 0).timestamp()),
                    "/v1/chat/completions",
                    "m",
                    "m",
                    200,
                    33.7,
                    "k",
                    None,
                    None,
                ),
            )
    finally:
        conn.close()
    monkeypatch.setenv("LOGUI_API_KEYS", "user-key")
    monkeypatch.setenv("LOGUI_DB_ROOT", str(base_dir))
    from ai_proxy_ui.main import app
    client = TestClient(app)
    r = client.get("/ui/v1/requests/rid-none", headers={"Authorization": "Bearer user-key"})
    assert r.status_code == 200
    data = r.json()
    assert data["request_json"] is None
    assert data["response_json"] is None

def test_iter_all_partitions_skips_non_matching_files(tmp_path, monkeypatch):
    base_dir = tmp_path / "logs" / "db" / "2025" / "09"
    os.makedirs(base_dir, exist_ok=True)
    # Create matching and non-matching files
    open(base_dir / "ai_proxy_20250910.sqlite3", "w").close()
    open(base_dir / "other_file.txt", "w").close()
    open(base_dir / "ai_proxy_20250911.db", "w").close()  # wrong extension
    open(base_dir / "wrong_prefix_20250912.sqlite3", "w").close()  # wrong prefix to hit line 357
    monkeypatch.setenv("LOGUI_API_KEYS", "user-key")
    monkeypatch.setenv("LOGUI_DB_ROOT", str(tmp_path / "logs" / "db"))
    from ai_proxy_ui.main import _iter_all_partitions
    # Direct call to test skips
    paths = _iter_all_partitions(str(tmp_path / "logs" / "db"))
    assert len(paths) == 1
    assert paths[0].endswith("ai_proxy_20250910.sqlite3")

def test_decode_cursor_invalid_base64_raises(monkeypatch):
    from ai_proxy_ui.main import _decode_cursor
    import pytest
    with pytest.raises(Exception) as exc:  # HTTPException in context
        _decode_cursor("not-base64!!!")
    assert "Invalid cursor" in str(exc.value)
