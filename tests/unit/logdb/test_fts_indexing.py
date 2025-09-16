import datetime as dt
import json
import os
import sqlite3
import pytest
from unittest import mock

from ai_proxy.logdb.fts import (
    build_partition_fts,
    build_fts_for_range,
)
from ai_proxy.logdb.schema import open_connection_with_pragmas
from ai_proxy.logdb.partitioning import compute_partition_path


@pytest.fixture
def temp_db_path(tmp_path):
    db_path = str(tmp_path / "test_fts.db")
    conn = open_connection_with_pragmas(db_path)
    conn.close()
    yield db_path
    if os.path.exists(db_path):
        os.remove(db_path)


# Tests for build_partition_fts
def test_build_partition_fts_success(temp_db_path):
    conn = open_connection_with_pragmas(temp_db_path)
    conn.executescript("""
        CREATE TABLE requests (
            request_id TEXT PRIMARY KEY,
            endpoint TEXT,
            model_original TEXT,
            model_mapped TEXT,
            request_json TEXT,
            response_json TEXT
        );
        INSERT INTO requests VALUES
            ('r1', 'chat', 'gpt', 'gpt-m', '{"messages": [{"content": "test"}]}', '{"choices": [{"message": {"content": "response"}}]}'),
            ('r2', 'chat', 'gemini', 'gem-m', '{"contents": [{"parts": [{"text": "q"}]}]}', '{"candidates": [{"content": {"parts": [{"text": "a"}]}}]}'),
            ('r3', '', '', '', '{}', '{}');  -- empty to skip
    """)
    conn.commit()
    conn.close()

    with mock.patch("ai_proxy.logdb.fts._sqlite_supports_fts5", return_value=True):
        indexed, skipped = build_partition_fts(temp_db_path)
        assert indexed == 4  # user test, assistant response, user q (gemini), assistant a
        assert skipped == 1


def test_build_partition_fts_large_content_cap(temp_db_path):
    conn = open_connection_with_pragmas(temp_db_path)
    large = "a" * 30000
    conn.execute("CREATE TABLE requests (request_id TEXT, endpoint TEXT, model_original TEXT, model_mapped TEXT, request_json TEXT, response_json TEXT);")
    conn.execute("INSERT INTO requests VALUES (?, ?, ?, ?, ?, ?);", ("r1", "", "", "", json.dumps({"messages": [{"content": large}]}), "{}"))
    conn.commit()
    conn.close()

    with mock.patch("ai_proxy.logdb.fts._sqlite_supports_fts5", return_value=True):
        indexed, skipped = build_partition_fts(temp_db_path)
        assert indexed == 1
        conn = sqlite3.connect(temp_db_path)
        content = conn.execute("SELECT content FROM request_text_index WHERE request_id='r1'").fetchone()[0]
        assert len(content) == 20000


def test_build_partition_fts_no_fts_support(temp_db_path):
    with mock.patch("ai_proxy.logdb.fts._sqlite_supports_fts5", return_value=False), pytest.raises(RuntimeError, match="SQLite build does not support FTS5"):
        build_partition_fts(temp_db_path)


def test_build_partition_fts_empty_fragments_skipped(temp_db_path):
    conn = open_connection_with_pragmas(temp_db_path)
    conn.execute("CREATE TABLE requests (request_id TEXT, endpoint TEXT, model_original TEXT, model_mapped TEXT, request_json TEXT, response_json TEXT);")
    conn.execute("INSERT INTO requests VALUES (?, ?, ?, ?, ?, ?);", ("r1", "", "", "", "{}", "{}"))
    conn.commit()
    conn.close()

    with mock.patch("ai_proxy.logdb.fts._sqlite_supports_fts5", return_value=True):
        indexed, skipped = build_partition_fts(temp_db_path)
        assert indexed == 0
        assert skipped == 1


def test_build_partition_fts_small_batch_no_mid_insert(temp_db_path):
    conn = open_connection_with_pragmas(temp_db_path)
    conn.execute("CREATE TABLE requests (request_id TEXT, endpoint TEXT, model_original TEXT, model_mapped TEXT, request_json TEXT, response_json TEXT);")
    conn.execute("INSERT INTO requests VALUES (?, ?, ?, ?, ?, ?);", ("r1", "", "", "", json.dumps({"messages": [{"content": "small"}]}), "{}"))
    conn.commit()
    conn.close()

    with mock.patch("ai_proxy.logdb.fts._sqlite_supports_fts5", return_value=True):
        indexed, skipped = build_partition_fts(temp_db_path)
        assert indexed == 1  # hits final batch insert, not mid


def test_build_partition_fts_large_batch(temp_db_path):
    conn = open_connection_with_pragmas(temp_db_path)
    conn.execute("CREATE TABLE requests (request_id TEXT PRIMARY KEY, endpoint TEXT, model_original TEXT, model_mapped TEXT, request_json TEXT, response_json TEXT);")
    for i in range(501):  # To trigger mid-batch at 500 and final
        req_json = json.dumps({"messages": [{"role": "user", "content": f"test {i}"}]})
        conn.execute("INSERT INTO requests VALUES (?, ?, ?, ?, ?, ?);", (f"r{i}", "chat", "model", "mapped", req_json, "{}"))
    conn.commit()
    conn.close()

    with mock.patch("ai_proxy.logdb.fts._sqlite_supports_fts5", return_value=True):
        indexed, skipped = build_partition_fts(temp_db_path)
        assert indexed == 501
        assert skipped == 0


# Tests for build_fts_for_range
def test_build_fts_for_range_multiple_existing(tmp_path):
    base_db = str(tmp_path / "db")
    d1 = dt.date(2025, 9, 1)
    d2 = dt.date(2025, 9, 2)
    p1 = _make_partition(base_db, d1)
    p2 = _make_partition(base_db, d2)

    with mock.patch("ai_proxy.logdb.fts._sqlite_supports_fts5", return_value=True), mock.patch("ai_proxy.logdb.fts.build_partition_fts", side_effect=lambda p: (5, 1) if p == p1 else (3, 0)):
        results = build_fts_for_range(base_db, d1, d2)
        assert len(results) == 2
        assert results[0] == (p1, 5, 1)
        assert results[1] == (p2, 3, 0)


def test_build_fts_for_range_non_existing(tmp_path):
    base_db = str(tmp_path / "db")
    d = dt.date(2025, 9, 1)
    results = build_fts_for_range(base_db, d, d)
    assert results == []  # Skips non-existing


def test_build_fts_for_range_defaults_to_today():
    today = dt.date(2025, 9, 1)
    with mock.patch("ai_proxy.logdb.fts.dt.date") as mock_date:
        mock_date.today.return_value = today
        mock_date.return_value = today  # For any date calls
        with mock.patch("ai_proxy.logdb.fts.os.path.isfile", return_value=False), \
             mock.patch("ai_proxy.logdb.fts.build_partition_fts") as mock_build:
            results = build_fts_for_range("/fake", None, None)
            assert results == []
            mock_build.assert_not_called()  # since no file


def test_build_fts_for_range_deduplicates_paths():
    with mock.patch("ai_proxy.logdb.fts.compute_partition_path", return_value="/same/path"), \
         mock.patch("ai_proxy.logdb.fts.build_partition_fts", return_value=(1,0)) as mock_build, \
         mock.patch("os.path.isfile", return_value=True):
        results = build_fts_for_range("/base", dt.date(2025,9,1), dt.date(2025,9,7))
        assert len(results) == 1
        mock_build.assert_called_once()


def test_build_fts_for_range_since_none():
    with mock.patch("ai_proxy.logdb.fts.build_partition_fts", return_value=(0,0)):
        to_date = dt.date(2025,9,1)
        results = build_fts_for_range("/fake", None, to_date)
        assert len(results) == 0  # sets since=to


def test_build_fts_for_range_to_none():
    with mock.patch("ai_proxy.logdb.fts.build_partition_fts", return_value=(0,0)):
        since_date = dt.date(2025,9,1)
        results = build_fts_for_range("/fake", since_date, None)
        assert len(results) == 0  # sets to=since


def _make_partition(base_dir: str, date: dt.date) -> str:
    db_path = compute_partition_path(base_dir, date)
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(
            """
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS requests (
              request_id TEXT PRIMARY KEY,
              endpoint TEXT,
              model_original TEXT,
              model_mapped TEXT,
              request_json TEXT,
              response_json TEXT
            );
            """
        )
        conn.commit()
    finally:
        conn.close()
    return db_path
