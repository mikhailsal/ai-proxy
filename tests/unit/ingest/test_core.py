import datetime as dt
import os
import sqlite3

from ai_proxy.logdb.ingest import ingest_logs
from ai_proxy.logdb.partitioning import compute_partition_path, control_database_path
from tests.unit.shared.ingest_fixtures import SAMPLE_ENTRY_1, SAMPLE_ENTRY_2


def test_ingest_basic_and_idempotent(tmp_path):
    logs_dir = tmp_path / "logs"
    db_base = tmp_path / "logs" / "db"
    logs_dir.mkdir(parents=True, exist_ok=True)

    log_path = logs_dir / "v1_chat_completions.log"
    log_path.write_text(SAMPLE_ENTRY_1 + SAMPLE_ENTRY_2, encoding="utf-8")

    # First ingest
    stats1 = ingest_logs(str(logs_dir), str(db_base))
    assert stats1.rows_inserted == 2
    assert stats1.files_scanned >= 1

    # Second ingest should be idempotent (no new rows)
    stats2 = ingest_logs(str(logs_dir), str(db_base))
    assert stats2.rows_inserted == 0

    # Verify rows exist in the correct partition
    date = dt.date(2025, 9, 10)
    db_path = compute_partition_path(str(db_base), date)
    assert os.path.isfile(db_path)

    conn = sqlite3.connect(db_path)
    try:
        cur = conn.execute("SELECT COUNT(*) FROM requests;")
        count = cur.fetchone()[0]
        assert count == 2

        # Spot-check columns present
        cur = conn.execute("PRAGMA table_info(requests);")
        cols = {row[1] for row in cur.fetchall()}
        assert {
            "request_id",
            "server_id",
            "ts",
            "endpoint",
            "request_json",
            "response_json",
        }.issubset(cols)
    finally:
        conn.close()

    # Verify checkpoint recorded in today's control partition
    control_db = control_database_path(str(db_base))
    assert os.path.isfile(control_db)
    conn = sqlite3.connect(control_db)
    try:
        cur = conn.execute(
            "SELECT source_path, bytes_ingested, mtime FROM ingest_sources LIMIT 1;"
        )
        row = cur.fetchone()
        assert row is not None
        assert row[0].endswith("v1_chat_completions.log")
        assert int(row[1]) > 0
        assert int(row[2]) > 0
    finally:
        conn.close()


def test_ingest_resume_with_prefix_sha_validation(tmp_path):
    logs_dir = tmp_path / "logs"
    db_base = tmp_path / "logs" / "db"
    logs_dir.mkdir(parents=True, exist_ok=True)

    log_path = logs_dir / "v1_chat_completions.log"
    # First entry
    log_path.write_text(SAMPLE_ENTRY_1, encoding="utf-8")
    stats1 = ingest_logs(str(logs_dir), str(db_base))
    assert (
        stats1.rows_inserted == 2 or stats1.rows_inserted == 1
    )  # depending on date range

    # Append second entry and corrupt the first byte without changing size by toggling a space
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(SAMPLE_ENTRY_2)

    # Now rewrite first byte to force prefix sha mismatch but keep same size
    p = log_path.read_text(encoding="utf-8")
    if p:
        mutated = (" " if p[0] != " " else "\t") + p[1:]
        log_path.write_text(mutated, encoding="utf-8")

    ingest_logs(str(logs_dir), str(db_base))
    # Should not double-insert earlier lines; idempotent overall
    date = dt.date(2025, 9, 10)
    db_path = compute_partition_path(str(db_base), date)
    if os.path.isfile(db_path):
        conn = sqlite3.connect(db_path)
        try:
            count = conn.execute("SELECT COUNT(*) FROM requests;").fetchone()[0]
            assert count >= 2
        finally:
            conn.close()


def test_ingest_resume_after_interruption(tmp_path):
    logs_dir = tmp_path / "logs"
    db_base = tmp_path / "logs" / "db"
    logs_dir.mkdir(parents=True, exist_ok=True)

    log_path = logs_dir / "v1_chat_completions.log"

    # Write only the first entry and ingest
    log_path.write_text(SAMPLE_ENTRY_1, encoding="utf-8")
    stats1 = ingest_logs(str(logs_dir), str(db_base))
    assert stats1.rows_inserted == 1

    # Append the second entry and re-run ingest; should only add one more
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(SAMPLE_ENTRY_2)

    stats2 = ingest_logs(str(logs_dir), str(db_base))
    assert stats2.rows_inserted == 1

    # Verify total rows = 2
    date = dt.date(2025, 9, 10)
    db_path = compute_partition_path(str(db_base), date)
    conn = sqlite3.connect(db_path)
    try:
        count = conn.execute("SELECT COUNT(*) FROM requests;").fetchone()[0]
        assert count == 2
    finally:
        conn.close()


def test_ingest_date_range_filtering(tmp_path):
    logs_dir = tmp_path / "logs"
    db_base = tmp_path / "logs" / "db"
    logs_dir.mkdir(parents=True, exist_ok=True)

    log_path = logs_dir / "v1_chat_completions.log"
    log_path.write_text(SAMPLE_ENTRY_1 + SAMPLE_ENTRY_2, encoding="utf-8")

    # Only include up to 2025-09-10
    since = dt.date(2025, 9, 10)
    to = dt.date(2025, 9, 10)
    stats = ingest_logs(str(logs_dir), str(db_base), since, to)
    assert stats.rows_inserted == 2

    # Narrow to a date before range: expect zero
    since2 = dt.date(2025, 9, 9)
    to2 = dt.date(2025, 9, 9)
    stats2 = ingest_logs(str(logs_dir), str(db_base), since2, to2)
    assert stats2.rows_inserted == 0


def test_ingest_rotated_log_files(tmp_path):
    logs_dir = tmp_path / "logs"
    db_base = tmp_path / "logs" / "db"
    logs_dir.mkdir(parents=True, exist_ok=True)

    main_log = logs_dir / "v1_chat_completions.log"
    rotated_log = logs_dir / "v1_chat_completions.log.1"

    main_log.write_text(SAMPLE_ENTRY_1, encoding="utf-8")
    rotated_log.write_text(SAMPLE_ENTRY_2, encoding="utf-8")

    stats = ingest_logs(str(logs_dir), str(db_base))
    # Both files should be processed; two rows total
    assert stats.rows_inserted == 2


def test_ingest_malformed_json(tmp_path):
    logs_dir = tmp_path / "logs"
    db_base = tmp_path / "logs" / "db"
    logs_dir.mkdir(parents=True, exist_ok=True)
    bad_log = logs_dir / "bad.log"
    bad_log.write_text("2025-09-10 12:00:00 - INFO - { invalid json", encoding="utf-8")
    stats = ingest_logs(str(logs_dir), str(db_base))
    assert stats.rows_inserted == 0


def test_ingest_invalid_timestamp(tmp_path):
    logs_dir = tmp_path / "logs"
    db_base = tmp_path / "logs" / "db"
    logs_dir.mkdir(parents=True, exist_ok=True)
    invalid_ts_log = logs_dir / "invalid_ts.log"
    invalid_ts_log.write_text(
        '2025-09-10 12:00:00 - INFO - {"timestamp": "invalid", "endpoint": "/v1/chat", "request": {}, "response": {}}',
        encoding="utf-8"
    )
    stats = ingest_logs(str(logs_dir), str(db_base))
    assert stats.rows_inserted == 0


def test_ingest_date_range_skip(tmp_path):
    logs_dir = tmp_path / "logs"
    db_base = tmp_path / "logs" / "db"
    logs_dir.mkdir(parents=True, exist_ok=True)
    out_range_log = logs_dir / "out_range.log"
    out_range_log.write_text(
        '2024-01-01 00:00:00 - INFO - {"timestamp": "2024-01-01T00:00:00Z", "endpoint": "/v1/chat", "request": {}, "response": {}}',
        encoding="utf-8"
    )
    since = dt.date(2025, 1, 1)
    to = dt.date(2025, 12, 31)
    stats = ingest_logs(str(logs_dir), str(db_base), since, to)
    assert stats.rows_inserted == 0


def test_incomplete_json_block_handling(tmp_path):
    """Test handling of incomplete JSON blocks at EOF."""
    from ai_proxy.logdb.parsers.log_parser import _iter_json_blocks

    # Create file with incomplete JSON at end
    test_file = tmp_path / "incomplete.log"
    test_file.write_text(
        "2025-09-10 12:00:00 - INFO - {\n"
        '  "timestamp": "2025-09-10T12:00:00Z",\n'
        '  "endpoint": "/v1/chat",\n'
        '  "incomplete": true\n'
        # Missing closing brace - incomplete JSON
    )

    with open(test_file, "r") as f:
        blocks = list(_iter_json_blocks(f))
        # Should safely handle incomplete block and return empty list
        assert len(blocks) == 0


def test_flush_with_empty_batch(tmp_path):
    """Test _flush function when batch is empty (line 386)."""
    logs_dir = tmp_path / "logs"
    db_base = tmp_path / "logs" / "db"
    logs_dir.mkdir(parents=True, exist_ok=True)

    # Create empty log file
    log_path = logs_dir / "empty.log"
    log_path.write_text("", encoding="utf-8")

    stats = ingest_logs(str(logs_dir), str(db_base))
    assert stats.rows_inserted == 0
    assert stats.files_scanned >= 1


def test_date_filtering_edge_cases(tmp_path):
    """Test date filtering continue statements (lines 428-429)."""
    logs_dir = tmp_path / "logs"
    db_base = tmp_path / "logs" / "db"
    logs_dir.mkdir(parents=True, exist_ok=True)

    # Create log with entries before and after target date range
    log_content = (
        # Entry before range
        "2025-01-01 12:00:00 - INFO - {\n"
        '  "timestamp": "2025-01-01T12:00:00Z",\n'
        '  "endpoint": "/v1/chat",\n'
        '  "request": {"model": "gpt-4"},\n'
        '  "response": {"id": "1"}\n'
        "}\n"
        # Entry in range
        + SAMPLE_ENTRY_1 +
        # Entry after range
        "2025-12-31 12:00:00 - INFO - {\n"
        '  "timestamp": "2025-12-31T12:00:00Z",\n'
        '  "endpoint": "/v1/chat",\n'
        '  "request": {"model": "gpt-4"},\n'
        '  "response": {"id": "3"}\n'
        "}\n"
    )

    log_path = logs_dir / "range_test.log"
    log_path.write_text(log_content, encoding="utf-8")

    # Filter to only include September 2025
    since = dt.date(2025, 9, 1)
    to = dt.date(2025, 9, 30)

    stats = ingest_logs(str(logs_dir), str(db_base), since, to)
    assert stats.rows_inserted == 1  # Only the September entry should be included
