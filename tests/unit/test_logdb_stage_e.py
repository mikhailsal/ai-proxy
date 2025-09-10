import datetime as dt
import os
import sqlite3

from ai_proxy.logdb.partitioning import ensure_partition_database, compute_partition_path
from ai_proxy.logdb.schema import open_connection_with_pragmas
from ai_proxy.logdb.dialogs import assign_partition_dialogs, assign_dialogs_for_range, _parse_window_to_seconds


def _insert_request(conn: sqlite3.Connection, request_id: str, ts: int, endpoint: str, model_mapped: str, api_key_hash: str) -> None:
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
    rc = logdb_cli.main(["dialogs", "assign", "--out", str(base), "--since", "2025-09-12", "--to", "2025-09-12"]) 
    assert rc == 2

    # Enabled case
    monkeypatch.setenv("LOGDB_GROUPING_ENABLED", "true")
    rc2 = logdb_cli.main(["dialogs", "assign", "--out", str(base), "--since", "2025-09-12", "--to", "2025-09-12", "--window", "30m"]) 
    assert rc2 == 0


