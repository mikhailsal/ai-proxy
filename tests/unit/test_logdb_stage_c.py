import datetime as dt
import os
import sqlite3

from ai_proxy.logdb.ingest import ingest_logs
from ai_proxy.logdb.partitioning import compute_partition_path


SAMPLE_ENTRY = (
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


def write_log(tmp_path):
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    log_path = logs_dir / "v1_chat_completions.log"
    log_path.write_text(SAMPLE_ENTRY, encoding="utf-8")
    return logs_dir


def test_server_id_persisted_file_and_servers_row(tmp_path, monkeypatch):
    db_base = tmp_path / "logs" / "db"
    logs_dir = write_log(tmp_path)

    # Ensure no overrides
    monkeypatch.delenv("LOGDB_SERVER_ID", raising=False)

    # First ingest writes .server_id and inserts one row
    stats1 = ingest_logs(str(logs_dir), str(db_base))
    assert stats1.rows_inserted == 1

    # .server_id file should exist
    server_id_file = db_base / ".server_id"
    assert server_id_file.is_file()
    persisted_id = server_id_file.read_text(encoding="utf-8").strip()
    assert persisted_id

    # Check that servers table contains that id
    date = dt.date(2025, 9, 10)
    db_path = compute_partition_path(str(db_base), date)
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute("SELECT server_id FROM servers LIMIT 1;").fetchone()
        assert row and row[0] == persisted_id
    finally:
        conn.close()

    # Second ingest should be idempotent and reuse same id
    stats2 = ingest_logs(str(logs_dir), str(db_base))
    assert stats2.rows_inserted == 0


def test_env_override_server_id_takes_priority(tmp_path, monkeypatch):
    db_base = tmp_path / "logs" / "db"
    logs_dir = write_log(tmp_path)

    # Create a conflicting persisted id first
    (db_base).mkdir(parents=True, exist_ok=True)
    (db_base / ".server_id").write_text("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", encoding="utf-8")

    # Override via env and ingest
    override_id = "11111111-2222-3333-4444-555555555555"
    monkeypatch.setenv("LOGDB_SERVER_ID", override_id)

    stats = ingest_logs(str(logs_dir), str(db_base))
    assert stats.rows_inserted == 1

    date = dt.date(2025, 9, 10)
    db_path = compute_partition_path(str(db_base), date)
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute("SELECT server_id FROM servers LIMIT 1;").fetchone()
        assert row and row[0] == override_id
    finally:
        conn.close()


def test_dedup_with_same_server_id_across_runs(tmp_path, monkeypatch):
    db_base = tmp_path / "logs" / "db"
    logs_dir = write_log(tmp_path)

    same_id = "99999999-aaaa-bbbb-cccc-dddddddddddd"
    monkeypatch.setenv("LOGDB_SERVER_ID", same_id)

    # First ingest
    stats1 = ingest_logs(str(logs_dir), str(db_base))
    assert stats1.rows_inserted == 1

    # Simulate "another host" with the same id doing the same ingest into the same DB
    stats2 = ingest_logs(str(logs_dir), str(db_base))
    assert stats2.rows_inserted == 0

    # Verify only one row
    date = dt.date(2025, 9, 10)
    db_path = compute_partition_path(str(db_base), date)
    conn = sqlite3.connect(db_path)
    try:
        count = conn.execute("SELECT COUNT(*) FROM requests;").fetchone()[0]
        assert count == 1
    finally:
        conn.close()


