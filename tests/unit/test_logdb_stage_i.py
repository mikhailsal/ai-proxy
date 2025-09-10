import os
import re
import sqlite3
import datetime as dt
from io import StringIO
from contextlib import redirect_stdout

from ai_proxy.logdb.ingest import ingest_logs
from ai_proxy.logdb.partitioning import compute_partition_path
from ai_proxy.logdb.schema import open_connection_with_pragmas

SAMPLE_TEMPLATE = (
    "2025-09-10 12:00:00 - INFO - {\n"
    "  \"timestamp\": \"__TS__\",\n"
    "  \"endpoint\": \"/v1/chat/completions\",\n"
    "  \"status_code\": 200,\n"
    "  \"latency_ms\": 1.2,\n"
    "  \"request\": {\n"
    "    \"model\": \"gpt-4\",\n"
    "    \"messages\": [{\"role\": \"user\", \"content\": \"Hi\"}]\n"
    "  },\n"
    "  \"response\": {\n"
    "    \"id\": \"r1\",\n"
    "    \"model\": \"mapped\",\n"
    "    \"choices\": [{\"index\": 0, \"message\": {\"role\": \"assistant\", \"content\": \"Hello\"}}]\n"
    "  }\n"
    "}\n"
)


def _sample_with_ts(ts: str) -> str:
    return SAMPLE_TEMPLATE.replace("__TS__", ts)


def test_wal_autocheckpoint_env_applied(tmp_path, monkeypatch):
    monkeypatch.setenv("LOGDB_WAL_AUTOCHECKPOINT_PAGES", "256")
    db = tmp_path / "db.sqlite3"
    conn = open_connection_with_pragmas(str(db))
    try:
        cur = conn.execute("PRAGMA wal_autocheckpoint;")
        val = int(cur.fetchone()[0])
        assert val == 256
    finally:
        conn.close()


def test_batch_rows_and_bytes_flush(tmp_path, monkeypatch):
    logs_dir = tmp_path / "logs"
    db_base = tmp_path / "logs" / "db"
    logs_dir.mkdir(parents=True, exist_ok=True)

    # Create a file with many entries to trigger row-based and byte-based flush
    entries = []
    for i in range(20):
        # unique timestamps to avoid INSERT OR IGNORE de-duplication
        ts = f"2025-09-10T12:00:{i:02d}Z"
        entries.append(_sample_with_ts(ts))
    (logs_dir / "v1_chat_completions.log").write_text("".join(entries), encoding="utf-8")

    # Set tiny batch sizes to force frequent flushes
    monkeypatch.setenv("LOGDB_BATCH_ROWS", "3")
    monkeypatch.setenv("LOGDB_BATCH_KB", "1")  # bytes ~1KB to trigger by size too

    stats = ingest_logs(str(logs_dir), str(db_base))
    assert stats.rows_inserted >= 10

    # Validate rows are in DB
    date = dt.date(2025, 9, 10)
    db_path = compute_partition_path(str(db_base), date)
    conn = sqlite3.connect(db_path)
    try:
        cnt = conn.execute("SELECT COUNT(*) FROM requests;").fetchone()[0]
        assert cnt == stats.rows_inserted
    finally:
        conn.close()


def test_perf_line_printed(tmp_path, monkeypatch):
    logs_dir = tmp_path / "logs"
    db_base = tmp_path / "logs" / "db"
    logs_dir.mkdir(parents=True, exist_ok=True)

    entries = []
    for i in range(5):
        ts = f"2025-09-10T12:01:{i:02d}Z"
        entries.append(_sample_with_ts(ts))
    (logs_dir / "v1_chat_completions.log").write_text("".join(entries), encoding="utf-8")

    buf = StringIO()
    with redirect_stdout(buf):
        stats = ingest_logs(str(logs_dir), str(db_base))
    out = buf.getvalue()

    assert "ingest_elapsed_s=" in out
    m = re.search(r"rps=([0-9]+\.[0-9]+)", out)
    assert m is not None
    assert float(m.group(1)) >= 0.0
