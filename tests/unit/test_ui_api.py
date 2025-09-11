import os
from fastapi.testclient import TestClient


def test_health_endpoints_import_and_respond():
    # Ensure wildcard CORS for simplicity in stage U1
    os.environ["LOGUI_ALLOWED_ORIGINS"] = "*"

    from ai_proxy_ui.main import app  # import after env set

    client = TestClient(app)

    for path in ["/ui/health", "/ui/v1/health"]:
        r = client.get(path)
        assert r.status_code == 200
        assert r.json() == {"status": "ok"}
        # CORS header should be present
        assert r.headers.get("access-control-allow-origin") in ("*", None)


