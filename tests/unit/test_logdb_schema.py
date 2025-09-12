import os
import sqlite3
import pytest
from unittest import mock

from ai_proxy.logdb.schema import open_connection_with_pragmas

@pytest.fixture
def temp_db_path(tmp_path):
    return str(tmp_path / "test.db")

def test_open_connection_with_pragmas_normal(temp_db_path, monkeypatch):
    monkeypatch.setenv("LOGDB_WAL_AUTOCHECKPOINT_PAGES", "1000")
    monkeypatch.setenv("LOGDB_SQLITE_CACHE_KB", "2000")

    conn = open_connection_with_pragmas(temp_db_path)
    try:
        # Verify WAL mode
        assert conn.execute("PRAGMA journal_mode;").fetchone()[0].lower() == "wal"
        # Verify custom pragmas applied
        wal_auto = conn.execute("PRAGMA wal_autocheckpoint;").fetchone()[0]
        assert wal_auto == 1000
        cache_size = conn.execute("PRAGMA cache_size;").fetchone()[0]
        assert cache_size == -2000
    finally:
        conn.close()

def test_open_connection_with_pragmas_invalid_env(temp_db_path, monkeypatch):
    def mock_getenv(key, default=None):
        if key == "LOGDB_WAL_AUTOCHECKPOINT_PAGES":
            return "invalid"  # Triggers ValueError in int()
        if key == "LOGDB_SQLITE_CACHE_KB":
            return "invalid"  # Triggers ValueError in int()
        return default

    with mock.patch("os.getenv", side_effect=mock_getenv):
        conn = open_connection_with_pragmas(temp_db_path)
        try:
            # Verify WAL mode still set (defaults should apply)
            assert conn.execute("PRAGMA journal_mode;").fetchone()[0].lower() == "wal"
            # Verify defaults used (custom pragmas skipped due to invalid env)
            wal_auto = conn.execute("PRAGMA wal_autocheckpoint;").fetchone()[0]
            assert wal_auto == 1000  # SQLite default
            cache_size = conn.execute("PRAGMA cache_size;").fetchone()[0]
            assert cache_size == -2000  # SQLite default in KB
        finally:
            conn.close()
