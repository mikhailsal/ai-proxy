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


