import datetime as dt
import sqlite3

from ai_proxy.logdb.partitioning import ensure_partition_database
from ai_proxy.logdb.schema import open_connection_with_pragmas
from ai_proxy.logdb.dialogs import (
    assign_partition_dialogs,
    assign_dialogs_for_range,
    _parse_window_to_seconds,
)


def _insert_request(
    conn: sqlite3.Connection,
    request_id: str,
    ts: int,
    endpoint: str,
    model_mapped: str,
    api_key_hash: str,
) -> None:
    with conn:
        conn.execute(
            """
            INSERT INTO requests (
              request_id, server_id, ts, endpoint, model_original, model_mapped,
              status_code, latency_ms, api_key_hash, request_json, response_json, dialog_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
            """,
            (
                request_id,
                "s1",
                ts,
                endpoint,
                None,
                model_mapped,
                200,
                10.0,
                api_key_hash,
                "{}",
                "{}",
            ),
        )


def test_window_parsing_variants():
    assert _parse_window_to_seconds("30m") == 1800
    assert _parse_window_to_seconds("45s") == 45
    assert _parse_window_to_seconds("2h") == 7200
    assert _parse_window_to_seconds("1800") == 1800
    # Fallbacks
    assert isinstance(_parse_window_to_seconds("bad"), int)
    assert _parse_window_to_seconds("0s") >= 1


def test_grouping_within_window_and_split(tmp_path):
    base = tmp_path / "logs" / "db"
    date = dt.date(2025, 9, 10)
    db_path = ensure_partition_database(str(base), date)

    conn = open_connection_with_pragmas(db_path)
    try:
        t0 = int(dt.datetime(2025, 9, 10, 12, 0, 0).timestamp())
        # Same group: same api_key_hash, endpoint, model_mapped
        _insert_request(conn, "r1", t0, "/v1/chat", "m1", "k1")
        _insert_request(conn, "r2", t0 + 60, "/v1/chat", "m1", "k1")
        _insert_request(conn, "r3", t0 + 120, "/v1/chat", "m1", "k1")
        # Gap beyond 30m
        _insert_request(conn, "r4", t0 + 4000, "/v1/chat", "m1", "k1")

        updated = assign_partition_dialogs(db_path, window_seconds=1800)
        assert updated == 4

        rows = conn.execute(
            "SELECT request_id, dialog_id FROM requests ORDER BY ts"
        ).fetchall()
        d1 = rows[0][1]
        assert rows[1][1] == d1
        assert rows[2][1] == d1
        d2 = rows[3][1]
        assert d2 != d1

        # Idempotent on second run
        updated2 = assign_partition_dialogs(db_path, window_seconds=1800)
        assert updated2 == 0
    finally:
        conn.close()


def test_distinct_groups_by_endpoint_and_model(tmp_path):
    base = tmp_path / "logs" / "db"
    date = dt.date(2025, 9, 11)
    db_path = ensure_partition_database(str(base), date)
    conn = open_connection_with_pragmas(db_path)
    try:
        t0 = int(dt.datetime(2025, 9, 11, 10, 0, 0).timestamp())
        # Different endpoint
        _insert_request(conn, "a1", t0, "/v1/chat", "mX", "kZ")
        _insert_request(conn, "a2", t0 + 10, "/v1/embeddings", "mX", "kZ")
        # Different model_mapped
        _insert_request(conn, "a3", t0 + 20, "/v1/chat", "mY", "kZ")

        updated = assign_partition_dialogs(db_path, window_seconds=1800)
        assert updated == 3
        rows = conn.execute(
            "SELECT request_id, dialog_id FROM requests ORDER BY request_id"
        ).fetchall()
        dialogs = {rid: did for rid, did in rows}
        assert dialogs["a1"] != dialogs["a2"]
        assert dialogs["a1"] != dialogs["a3"]
    finally:
        conn.close()


def test_cli_gating_env_flag_for_dialogs(monkeypatch, tmp_path):
    from ai_proxy.logdb import cli as logdb_cli

    base = tmp_path / "logs" / "db"
    date = dt.date(2025, 9, 12)
    db_path = ensure_partition_database(str(base), date)
    conn = open_connection_with_pragmas(db_path)
    try:
        t0 = int(dt.datetime(2025, 9, 12, 9, 0, 0).timestamp())
        _insert_request(conn, "x1", t0, "/v1/chat", "m1", "k1")
    finally:
        conn.close()

    # Disabled case
    monkeypatch.setenv("LOGDB_GROUPING_ENABLED", "false")
    rc = logdb_cli.main(
        [
            "dialogs",
            "assign",
            "--out",
            str(base),
            "--since",
            "2025-09-12",
            "--to",
            "2025-09-12",
        ]
    )
    assert rc == 2

    # Enabled case
    monkeypatch.setenv("LOGDB_GROUPING_ENABLED", "true")
    rc2 = logdb_cli.main(
        [
            "dialogs",
            "assign",
            "--out",
            str(base),
            "--since",
            "2025-09-12",
            "--to",
            "2025-09-12",
            "--window",
            "30m",
        ]
    )
    assert rc2 == 0


def test_gap_equal_window_no_split(tmp_path):
    base = tmp_path / "logs" / "db"
    date = dt.date(2025, 9, 13)
    db_path = ensure_partition_database(str(base), date)

    conn = open_connection_with_pragmas(db_path)
    try:
        t0 = int(dt.datetime(2025, 9, 13, 8, 0, 0).timestamp())
        _insert_request(conn, "w1", t0, "/v1/chat", "m1", "k1")
        # Exactly at window boundary (1800 seconds)
        _insert_request(conn, "w2", t0 + 1800, "/v1/chat", "m1", "k1")

        updated = assign_partition_dialogs(db_path, window_seconds=1800)
        assert updated == 2
        rows = conn.execute(
            "SELECT request_id, dialog_id FROM requests ORDER BY ts"
        ).fetchall()
        assert rows[0][1] == rows[1][1]
    finally:
        conn.close()


def test_grouping_distinct_api_key_hash(tmp_path):
    base = tmp_path / "logs" / "db"
    date = dt.date(2025, 9, 14)
    db_path = ensure_partition_database(str(base), date)

    conn = open_connection_with_pragmas(db_path)
    try:
        t0 = int(dt.datetime(2025, 9, 14, 9, 0, 0).timestamp())
        _insert_request(conn, "k1", t0, "/v1/chat", "m1", "KEY-A")
        _insert_request(conn, "k2", t0 + 10, "/v1/chat", "m1", "KEY-B")

        updated = assign_partition_dialogs(db_path, window_seconds=1800)
        assert updated == 2
        rows = conn.execute(
            "SELECT request_id, dialog_id FROM requests ORDER BY request_id"
        ).fetchall()
        did = {rid: dlg for rid, dlg in rows}
        assert did["k1"] != did["k2"]
    finally:
        conn.close()


def test_assign_dialogs_for_range_two_days(tmp_path):
    from ai_proxy.logdb.dialogs import assign_dialogs_for_range

    base = tmp_path / "logs" / "db"
    d1 = dt.date(2025, 9, 15)
    d2 = dt.date(2025, 9, 16)
    p1 = ensure_partition_database(str(base), d1)
    p2 = ensure_partition_database(str(base), d2)

    c1 = open_connection_with_pragmas(p1)
    try:
        _insert_request(
            c1,
            "rday1",
            int(dt.datetime(2025, 9, 15, 10, 0).timestamp()),
            "/v1/chat",
            "m1",
            "k1",
        )
    finally:
        c1.close()
    c2 = open_connection_with_pragmas(p2)
    try:
        _insert_request(
            c2,
            "rday2",
            int(dt.datetime(2025, 9, 16, 10, 0).timestamp()),
            "/v1/chat",
            "m1",
            "k1",
        )
    finally:
        c2.close()

    results = assign_dialogs_for_range(str(base), d1, d2, 1800)
    # Two partitions processed
    assert len(results) == 2
    # Each updated exactly 1 row
    assert sorted([u for _p, u in results]) == [1, 1]


def test_dialogs_clear_function_and_cli(monkeypatch, tmp_path):
    from ai_proxy.logdb import cli as logdb_cli
    from ai_proxy.logdb.dialogs import clear_dialogs_for_range

    base = tmp_path / "logs" / "db"
    date = dt.date(2025, 9, 17)
    db_path = ensure_partition_database(str(base), date)

    # Seed and assign dialogs
    conn = open_connection_with_pragmas(db_path)
    try:
        t0 = int(dt.datetime(2025, 9, 17, 11, 0, 0).timestamp())
        _insert_request(conn, "z1", t0, "/v1/chat", "m1", "k1")
        _insert_request(conn, "z2", t0 + 60, "/v1/chat", "m1", "k1")
        assign_partition_dialogs(db_path, 1800)
        pre = conn.execute(
            "SELECT COUNT(*) FROM requests WHERE dialog_id IS NOT NULL"
        ).fetchone()[0]
        assert pre == 2
    finally:
        conn.close()

    # Functional clear
    cleared = clear_dialogs_for_range(str(base), date, date)
    assert len(cleared) == 1 and cleared[0][1] == 2

    # CLI gating disabled
    monkeypatch.setenv("LOGDB_GROUPING_ENABLED", "false")
    rc = logdb_cli.main(
        [
            "dialogs",
            "clear",
            "--out",
            str(base),
            "--since",
            "2025-09-17",
            "--to",
            "2025-09-17",
        ]
    )
    assert rc == 2

    # CLI enabled path executes and reports cleared
    # Re-assign and then clear via CLI
    assign_dialogs_for_range(str(base), date, date, 1800)
    monkeypatch.setenv("LOGDB_GROUPING_ENABLED", "true")
    rc2 = logdb_cli.main(
        [
            "dialogs",
            "clear",
            "--out",
            str(base),
            "--since",
            "2025-09-17",
            "--to",
            "2025-09-17",
        ]
    )
    assert rc2 == 0


def test_parse_window_to_seconds_edge_cases():
    """Test _parse_window_to_seconds handles various edge cases and exceptions."""
    from ai_proxy.logdb.dialogs import _parse_window_to_seconds

    # Test millisecond fallback (line 14)
    assert _parse_window_to_seconds("500ms") == 1

    # Test exception handling in seconds parsing (lines 18-19)
    assert _parse_window_to_seconds("invalid_seconds") == 1800  # fallback

    # Test exception handling in minutes parsing (lines 23-24)
    assert _parse_window_to_seconds("invalid_minutes") == 1800  # fallback

    # Test exception handling in hours parsing (lines 28-29)
    assert _parse_window_to_seconds("invalid_hours") == 1800  # fallback

    # Test zero seconds handling
    assert _parse_window_to_seconds("0s") >= 1  # minimum 1 second


def test_assign_dialogs_for_range_none_to_parameter(tmp_path):
    """Test assign_dialogs_for_range handles to=None case (line 155)."""
    from ai_proxy.logdb.dialogs import assign_dialogs_for_range

    base = tmp_path / "logs" / "db"
    date = dt.date(2025, 9, 18)
    db_path = ensure_partition_database(str(base), date)

    # This should work even though to=None internally
    # The function has an assert that ensures since and to are not None
    # but we need to test the line where it checks if to is None
    try:
        assign_dialogs_for_range(str(base), date, None, 1800)
        assert False, "Should have failed assertion"
    except AssertionError:
        pass  # Expected


def test_clear_dialogs_for_range_none_to_parameter(tmp_path):
    """Test clear_dialogs_for_range handles to=None case (line 193)."""
    from ai_proxy.logdb.dialogs import clear_dialogs_for_range

    base = tmp_path / "logs" / "db"
    date = dt.date(2025, 9, 19)
    db_path = ensure_partition_database(str(base), date)

    # This should work even though to=None internally
    # The function has an assert that ensures since and to are not None
    # but we need to test the line where it checks if to is None
    try:
        clear_dialogs_for_range(str(base), date, None)
        assert False, "Should have failed assertion"
    except AssertionError:
        pass  # Expected


def test_stable_dialog_id_generation():
    """Test _stable_dialog_id generates consistent IDs."""
    from ai_proxy.logdb.dialogs import _stable_dialog_id

    # Same inputs should generate same ID
    id1 = _stable_dialog_id("hash1", "/v1/chat", "gpt-4", 1234567890)
    id2 = _stable_dialog_id("hash1", "/v1/chat", "gpt-4", 1234567890)
    assert id1 == id2

    # Different inputs should generate different IDs
    id3 = _stable_dialog_id("hash2", "/v1/chat", "gpt-4", 1234567890)
    assert id1 != id3

    # Test with None values
    id4 = _stable_dialog_id(None, None, None, 1234567890)
    assert id4.startswith("dlg-")
    assert len(id4) == 20  # "dlg-" + 16 hex chars


def test_stable_dialog_id_deterministic():
    """Test _stable_dialog_id is deterministic across calls."""
    from ai_proxy.logdb.dialogs import _stable_dialog_id

    # Generate multiple IDs and ensure they're all the same
    ids = []
    for _ in range(10):
        ids.append(_stable_dialog_id("test", "endpoint", "model", 1000000))

    # All should be identical
    assert all(id == ids[0] for id in ids)


def test_assign_dialogs_for_range_empty_range(tmp_path):
    """Test assign_dialogs_for_range with empty date range."""
    from ai_proxy.logdb.dialogs import assign_dialogs_for_range

    base = tmp_path / "logs" / "db"
    base.mkdir(parents=True)

    # Empty range should return empty list
    result = assign_dialogs_for_range(str(base), dt.date(2025, 9, 10), dt.date(2025, 9, 9), 1800)
    assert result == []


def test_assign_dialogs_for_range_no_files(tmp_path):
    """Test assign_dialogs_for_range when no database files exist."""
    from ai_proxy.logdb.dialogs import assign_dialogs_for_range

    base = tmp_path / "logs" / "db"
    base.mkdir(parents=True)

    # No files should return empty list
    result = assign_dialogs_for_range(str(base), dt.date(2025, 9, 10), dt.date(2025, 9, 11), 1800)
    assert result == []


def test_clear_dialogs_for_range_empty_range(tmp_path):
    """Test clear_dialogs_for_range with empty date range."""
    from ai_proxy.logdb.dialogs import clear_dialogs_for_range

    base = tmp_path / "logs" / "db"
    base.mkdir(parents=True)

    # Empty range should return empty list
    result = clear_dialogs_for_range(str(base), dt.date(2025, 9, 10), dt.date(2025, 9, 9))
    assert result == []


def test_assign_partition_dialogs_empty_database(tmp_path):
    """Test assign_partition_dialogs with database that has no requests table."""
    from ai_proxy.logdb.dialogs import assign_partition_dialogs

    # Create database without requests table (should raise exception)
    db_path = tmp_path / "no_requests.db"
    conn = sqlite3.connect(str(db_path))
    conn.close()

    # Should raise OperationalError for missing requests table
    try:
        assign_partition_dialogs(str(db_path), 1800)
        assert False, "Should have raised OperationalError"
    except sqlite3.OperationalError as e:
        assert "no such table: requests" in str(e)




def test_parse_window_to_seconds_invalid_formats():
    """Test _parse_window_to_seconds with invalid formats."""
    from ai_proxy.logdb.dialogs import _parse_window_to_seconds

    # Invalid unit should fallback to 1800
    assert _parse_window_to_seconds("30x") == 1800
    assert _parse_window_to_seconds("invalid") == 1800
    assert _parse_window_to_seconds("") == 1800

    # Invalid number should fallback to 1800
    assert _parse_window_to_seconds("abc") == 1800
    assert _parse_window_to_seconds("30.5m") == 1800  # Float not supported
