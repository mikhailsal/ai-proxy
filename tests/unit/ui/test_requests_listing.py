import datetime as dt
from fastapi.testclient import TestClient
from tests.unit.ui.test_models_helpers import _make_partition


def test_requests_listing_cross_partitions_and_pagination(tmp_path, monkeypatch):
    # Prepare two daily partitions under logs/db/YYYY/MM
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
    base_ts1 = int(dt.datetime(d1.year, d1.month, d1.day, 12, 0).timestamp())
    base_ts2 = int(dt.datetime(d2.year, d2.month, d2.day, 12, 0).timestamp())
    _make_partition(str(p1), rows=3, base_ts=base_ts1, start_id=0)
    _make_partition(str(p2), rows=2, base_ts=base_ts2, start_id=100)

    monkeypatch.setenv("LOGUI_API_KEYS", "user-key")
    monkeypatch.setenv("LOGUI_RATE_LIMIT_RPS", "1000")
    monkeypatch.setenv("LOGUI_DB_ROOT", str(base_dir))

    from ai_proxy_ui.main import app

    client = TestClient(app)

    r = client.get(
        "/ui/v1/requests",
        params={"since": str(d1), "to": str(d2), "limit": 3},
        headers={"Authorization": "Bearer user-key"},
    )
    assert r.status_code == 200
    data = r.json()
    assert len(data["items"]) == 3
    assert data["nextCursor"]
    ts_list = [it["ts"] for it in data["items"]]
    assert ts_list == sorted(ts_list, reverse=True)

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
    assert len(data2["items"]) == 2
    assert data2["nextCursor"] is None
