import datetime as dt
import os
import sqlite3

from ai_proxy.logdb.ingest import ingest_logs
from ai_proxy.logdb.partitioning import compute_partition_path


SAMPLE_ENTRY_1 = (
    "2025-09-10 12:00:00 - INFO - {\n"
    "  \"timestamp\": \"2025-09-10T12:00:00Z\",\n"
    "  \"endpoint\": \"/v1/chat/completions\",\n"
    "  \"status_code\": 200,\n"
    "  \"latency_ms\": 123.45,\n"
    "  \"request\": {\n"
    "    \"model\": \"gpt-4\",\n"
    "    \"messages\": [{\"role\": \"user\", \"content\": \"Hi\"}]\n"
    "  },\n"
    "  \"response\": {\n"
    "    \"id\": \"chatcmpl-1\",\n"
    "    \"model\": \"openrouter/openai/gpt-4\",\n"
    "    \"choices\": [{\"index\": 0, \"message\": {\"role\": \"assistant\", \"content\": \"Hello\"}}]\n"
    "  }\n"
    "}\n"
)


SAMPLE_ENTRY_2 = (
    "2025-09-10 12:05:00 - INFO - {\n"
    "  \"timestamp\": \"2025-09-10T12:05:00Z\",\n"
    "  \"endpoint\": \"/v1/chat/completions\",\n"
    "  \"status_code\": 200,\n"
    "  \"latency_ms\": 98.7,\n"
    "  \"request\": {\n"
    "    \"model\": \"gemini-pro\",\n"
    "    \"messages\": [{\"role\": \"user\", \"content\": \"Count 1-3\"}]\n"
    "  },\n"
    "  \"response\": {\n"
    "    \"id\": \"chatcmpl-2\",\n"
    "    \"model\": \"gemini:gemini-2.0-flash-001\",\n"
    "    \"choices\": [{\"index\": 0, \"message\": {\"role\": \"assistant\", \"content\": \"1,2,3\"}}]\n"
    "  }\n"
    "}\n"
)


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
        assert {"request_id", "server_id", "ts", "endpoint", "request_json", "response_json"}.issubset(cols)
    finally:
        conn.close()

    # Verify checkpoint recorded in today's control partition
    today = dt.date.today()
    control_db = compute_partition_path(str(db_base), today)
    assert os.path.isfile(control_db)
    conn = sqlite3.connect(control_db)
    try:
        cur = conn.execute("SELECT source_path, bytes_ingested, mtime FROM ingest_sources LIMIT 1;")
        row = cur.fetchone()
        assert row is not None
        assert row[0].endswith("v1_chat_completions.log")
        assert int(row[1]) > 0
        assert int(row[2]) > 0
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


def test_cli_gating_env_flags_for_ingest(monkeypatch, tmp_path):
    # Ensure gating: when LOGDB_ENABLED != true, CLI should return code 2
    from ai_proxy.logdb import cli as logdb_cli
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    (logs_dir / "v1_chat_completions.log").write_text(SAMPLE_ENTRY_1, encoding="utf-8")

    # Disabled case
    monkeypatch.setenv("LOGDB_ENABLED", "false")
    rc = logdb_cli.main(["ingest", "--from", str(logs_dir), "--out", str(tmp_path / "logs" / "db")])
    assert rc == 2

    # Enabled case
    monkeypatch.setenv("LOGDB_ENABLED", "true")
    rc2 = logdb_cli.main(["ingest", "--from", str(logs_dir), "--out", str(tmp_path / "logs" / "db")])
    assert rc2 == 0


