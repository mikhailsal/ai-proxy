import datetime as dt
import os
import sqlite3

from ai_proxy.logdb import (
    compute_partition_path,
    ensure_partition_database,
    open_connection_with_pragmas,
    run_integrity_check,
)


def test_compute_partition_path_layout(tmp_path):
    base = tmp_path / "logs" / "db"
    date = dt.date(2025, 9, 10)
    path = compute_partition_path(str(base), date)
    assert path.endswith("/2025/09/ai_proxy_20250910.sqlite3")


def test_compute_partition_path_weekly_layout(tmp_path, monkeypatch):
    base = tmp_path / "logs" / "db"
    date = dt.date(2025, 1, 2)  # 2025-W01 (ISO)
    monkeypatch.setenv("LOGDB_PARTITION_GRANULARITY", "weekly")
    path = compute_partition_path(str(base), date)
    assert "/2025/W01/ai_proxy_2025W01.sqlite3" in path
    # ensure DB creation works for weekly
    db_path = ensure_partition_database(str(base), date)
    assert os.path.isfile(db_path)


def test_ensure_partition_database_creates_schema(tmp_path):
    base = tmp_path / "logs" / "db"
    date = dt.date.today()
    db_path = ensure_partition_database(str(base), date)

    assert os.path.isfile(db_path)

    conn = sqlite3.connect(db_path)
    try:
        # journal_mode should be WAL after open_connection_with_pragmas; validate explicitly
        cur = conn.execute("PRAGMA journal_mode;")
        mode = cur.fetchone()[0].lower()
        assert mode == "wal"

        # Check required tables
        tables = {
            r[0]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table';"
            ).fetchall()
        }
        assert {"servers", "requests", "ingest_sources"}.issubset(tables)

        # Check required indexes exist
        indexes = {
            r[0]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index';"
            ).fetchall()
        }
        expected_indexes = {
            "idx_requests_ts",
            "idx_requests_endpoint",
            "idx_requests_status",
            "idx_requests_model_orig",
            "idx_requests_model_mapped",
            "idx_requests_api",
        }
        assert expected_indexes.issubset(indexes)
    finally:
        conn.close()


def test_integrity_check_ok(tmp_path):
    base = tmp_path / "logs" / "db"
    date = dt.date.today()
    db_path = ensure_partition_database(str(base), date)
    conn = open_connection_with_pragmas(db_path)
    try:
        assert run_integrity_check(conn) == "ok"
    finally:
        conn.close()


def test_create_two_partitions_today_and_yesterday(tmp_path):
    base = tmp_path / "logs" / "db"
    today = dt.date.today()
    yesterday = today - dt.timedelta(days=1)

    db_today = ensure_partition_database(str(base), today)
    db_yesterday = ensure_partition_database(str(base), yesterday)

    assert os.path.isfile(db_today)
    assert os.path.isfile(db_yesterday)

    # Both should pass integrity_check
    for path in (db_today, db_yesterday):
        conn = open_connection_with_pragmas(path)
        try:
            assert run_integrity_check(conn) == "ok"
        finally:
            conn.close()
