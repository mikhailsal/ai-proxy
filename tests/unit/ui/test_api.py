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


def test_rate_limit_enforced_per_key(monkeypatch):
    monkeypatch.setenv("LOGUI_API_KEYS", "user-key")
    monkeypatch.setenv("LOGUI_RATE_LIMIT_RPS", "2")

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


def test_auth_empty_token_raises_401(monkeypatch):
    monkeypatch.setenv("LOGUI_API_KEYS", "user-key")
    from ai_proxy_ui.main import app
    client = TestClient(app)
    r = client.get("/ui/v1/health", headers={"Authorization": "Bearer "})
    assert r.status_code == 401
    body = r.json()
    assert body["message"] == "Empty token"


def test_rate_limit_invalid_rps_falls_back(monkeypatch):
    monkeypatch.setenv("LOGUI_API_KEYS", "user-key")
    monkeypatch.setenv("LOGUI_RATE_LIMIT_RPS", "invalid")
    from ai_proxy_ui.main import app
    from ai_proxy_ui.services.auth import _rate_limit_buckets, _rate_limit_cached_rps as _auth_rate_limit_cached
    # Clear any existing rate limit state
    _rate_limit_buckets.clear()
    # Reset cached RPS to force re-evaluation of environment variable
    import ai_proxy_ui.services.auth as auth_module
    auth_module._rate_limit_cached_rps = None
    # Make time deterministic so all requests fall into the same window
    import time as _time
    fixed_sec = int(_time.time())
    auth_module.time.time = lambda: fixed_sec
    client = TestClient(app)
    # Make requests to trigger the fallback path
    for _ in range(11):  # Default is 10, so 11th should 429
        r = client.get("/ui/v1/health", headers={"Authorization": "Bearer user-key"})
    # Restore time.time to real function to avoid side effects
    import importlib
    importlib.reload(auth_module)
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
    # Direct import to test helper; helpers live in routers.requests after refactor
    from ai_proxy_ui.routers.requests import _parse_date_param
    import pytest
    with pytest.raises(Exception) as exc:
        _parse_date_param(None, None)
    assert "Missing date parameter" in str(exc.value)
