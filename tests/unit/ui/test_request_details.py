# New file with request details tests
import os
import datetime as dt
from fastapi.testclient import TestClient
import time


def test_iter_all_partitions_optimized_basic_functionality(tmp_path):
    """Test that _iter_all_partitions_optimized correctly discovers partition files."""
    from ai_proxy_ui.routers.requests import _iter_all_partitions_optimized

    base_dir = tmp_path / "logs" / "db"

    # Create some partition files in different directories
    files_to_create = [
        base_dir / "2025" / "09" / "ai_proxy_20250901.sqlite3",
        base_dir / "2025" / "09" / "ai_proxy_20250902.sqlite3",
        base_dir / "2025" / "W36" / "ai_proxy_2025W36.sqlite3",
        base_dir / "2025" / "M09" / "ai_proxy_202509.sqlite3",
    ]

    # Create non-matching files that should be ignored
    non_matching_files = [
        base_dir / "2025" / "09" / "other_file.sqlite3",  # Wrong prefix
        base_dir / "2025" / "09" / "ai_proxy_20250903.db",  # Wrong extension
        base_dir / "2025" / "09" / "ai_proxy_20250904.txt",  # Wrong extension
    ]

    # Create all files
    for file_path in files_to_create + non_matching_files:
        os.makedirs(file_path.parent, exist_ok=True)
        file_path.touch()
        # Add small delay to ensure different modification times
        time.sleep(0.01)

    # Test the function
    result = _iter_all_partitions_optimized(str(base_dir))

    # Should find only the matching files
    assert len(result) == 4

    # All results should be absolute paths to existing files
    for path in result:
        assert os.path.isabs(path)
        assert os.path.isfile(path)
        assert path.endswith(".sqlite3")
        assert "ai_proxy_" in os.path.basename(path)

    # Results should be sorted by modification time (newest first)
    mod_times = [os.path.getmtime(path) for path in result]
    assert mod_times == sorted(mod_times, reverse=True)


def test_iter_all_partitions_optimized_empty_directory(tmp_path):
    """Test behavior with empty directory."""
    from ai_proxy_ui.routers.requests import _iter_all_partitions_optimized

    base_dir = tmp_path / "empty_logs" / "db"
    os.makedirs(base_dir, exist_ok=True)

    result = _iter_all_partitions_optimized(str(base_dir))
    assert result == []


def test_iter_all_partitions_optimized_nonexistent_directory(tmp_path):
    """Test behavior with non-existent directory."""
    from ai_proxy_ui.routers.requests import _iter_all_partitions_optimized

    nonexistent_dir = tmp_path / "nonexistent"

    result = _iter_all_partitions_optimized(str(nonexistent_dir))
    assert result == []


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


def test_request_details_with_multiple_partitions(tmp_path, monkeypatch):
    """Test that request details endpoint searches across multiple partition files efficiently."""
    from tests.unit.ui.test_models_helpers import _make_partition

    base_dir = tmp_path / "logs" / "db"

    # Create multiple partitions
    d1 = dt.date(2025, 9, 1)
    d2 = dt.date(2025, 9, 2)
    d3 = dt.date(2025, 9, 3)

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
    p3 = (
        base_dir
        / f"{d3.year:04d}"
        / f"{d3.month:02d}"
        / f"ai_proxy_{d3.strftime('%Y%m%d')}.sqlite3"
    )

    base_ts1 = int(dt.datetime(d1.year, d1.month, d1.day, 12, 0).timestamp())
    base_ts2 = int(dt.datetime(d2.year, d2.month, d2.day, 12, 0).timestamp())
    base_ts3 = int(dt.datetime(d3.year, d3.month, d3.day, 12, 0).timestamp())

    _make_partition(str(p1), rows=2, base_ts=base_ts1, start_id=0)
    _make_partition(str(p2), rows=2, base_ts=base_ts2, start_id=100)
    _make_partition(str(p3), rows=2, base_ts=base_ts3, start_id=200)

    monkeypatch.setenv("LOGUI_API_KEYS", "user-key")
    monkeypatch.setenv("LOGUI_DB_ROOT", str(base_dir))

    from ai_proxy_ui.main import app

    client = TestClient(app)

    # Test finding request from first partition
    r1 = client.get(
        "/ui/v1/requests/t0000", headers={"Authorization": "Bearer user-key"}
    )
    assert r1.status_code == 200
    assert r1.json()["request_id"] == "t0000"

    # Test finding request from second partition
    r2 = client.get(
        "/ui/v1/requests/t0100", headers={"Authorization": "Bearer user-key"}
    )
    assert r2.status_code == 200
    assert r2.json()["request_id"] == "t0100"

    # Test finding request from third partition
    r3 = client.get(
        "/ui/v1/requests/t0200", headers={"Authorization": "Bearer user-key"}
    )
    assert r3.status_code == 200
    assert r3.json()["request_id"] == "t0200"


def test_request_details_with_invalid_json_handling(tmp_path, monkeypatch):
    """Test that request details endpoint handles invalid JSON gracefully."""
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
            # Insert record with invalid JSON
            conn.execute(
                "INSERT OR IGNORE INTO requests(request_id, server_id, ts, endpoint, model_original, model_mapped, status_code, latency_ms, api_key_hash, request_json, response_json, dialog_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,NULL)",
                (
                    "rid-invalid-json",
                    "srv-1",
                    int(dt.datetime(d.year, d.month, d.day, 12, 0).timestamp()),
                    "/v1/chat/completions",
                    "m",
                    None,  # model_mapped is NULL
                    None,  # status_code is NULL
                    None,  # latency_ms is NULL
                    "k",
                    "invalid json string {",  # Invalid JSON
                    "also invalid }",  # Invalid JSON
                ),
            )
    finally:
        conn.close()

    monkeypatch.setenv("LOGUI_API_KEYS", "user-key")
    monkeypatch.setenv("LOGUI_DB_ROOT", str(base_dir))

    from ai_proxy_ui.main import app

    client = TestClient(app)

    r = client.get(
        "/ui/v1/requests/rid-invalid-json", headers={"Authorization": "Bearer user-key"}
    )
    assert r.status_code == 200
    data = r.json()
    assert data["request_id"] == "rid-invalid-json"
    assert data["model_mapped"] is None
    assert data["status_code"] is None
    assert data["latency_ms"] is None
    # Invalid JSON should be returned as string
    assert isinstance(data["request_json"], str)
    assert isinstance(data["response_json"], str)
    assert data["request_json"] == "invalid json string {"
    assert data["response_json"] == "also invalid }"


def test_request_details_no_partition_files(tmp_path, monkeypatch):
    """Test behavior when no partition files exist."""
    base_dir = tmp_path / "logs" / "db"
    os.makedirs(base_dir, exist_ok=True)

    monkeypatch.setenv("LOGUI_API_KEYS", "user-key")
    monkeypatch.setenv("LOGUI_DB_ROOT", str(base_dir))

    from ai_proxy_ui.main import app

    client = TestClient(app)

    r = client.get(
        "/ui/v1/requests/any-id", headers={"Authorization": "Bearer user-key"}
    )
    assert r.status_code == 404
    assert "Request not found" in r.json()["message"]


def test_request_details_with_corrupted_database(tmp_path, monkeypatch):
    """Test that request details endpoint handles corrupted database files gracefully."""
    from tests.unit.ui.test_models_helpers import _make_partition

    base_dir = tmp_path / "logs" / "db"
    d1 = dt.date(2025, 9, 1)
    d2 = dt.date(2025, 9, 2)

    # Create a valid partition with target request
    p1 = (
        base_dir
        / f"{d1.year:04d}"
        / f"{d1.month:02d}"
        / f"ai_proxy_{d1.strftime('%Y%m%d')}.sqlite3"
    )
    base_ts1 = int(dt.datetime(d1.year, d1.month, d1.day, 12, 0).timestamp())
    _make_partition(str(p1), rows=2, base_ts=base_ts1, start_id=0)

    # Create a corrupted database file (should be skipped)
    p2 = (
        base_dir
        / f"{d2.year:04d}"
        / f"{d2.month:02d}"
        / f"ai_proxy_{d2.strftime('%Y%m%d')}.sqlite3"
    )
    os.makedirs(os.path.dirname(p2), exist_ok=True)
    # Write invalid SQLite data
    with open(p2, "wb") as f:
        f.write(b"this is not a valid sqlite database file")

    monkeypatch.setenv("LOGUI_API_KEYS", "user-key")
    monkeypatch.setenv("LOGUI_DB_ROOT", str(base_dir))

    from ai_proxy_ui.main import app

    client = TestClient(app)

    # Should find the request from valid partition, skipping corrupted one
    r = client.get(
        "/ui/v1/requests/t0000", headers={"Authorization": "Bearer user-key"}
    )
    assert r.status_code == 200
    assert r.json()["request_id"] == "t0000"

    # Should return 404 for request that would only be in corrupted file
    r2 = client.get(
        "/ui/v1/requests/nonexistent", headers={"Authorization": "Bearer user-key"}
    )
    assert r2.status_code == 404
