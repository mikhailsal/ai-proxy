import datetime as dt
import sqlite3
import os

from ai_proxy.logdb.partitioning import compute_partition_path


def _prepare_db_with_rows(tmp_path):
    db_base = tmp_path / "logs" / "db"
    date = dt.date(2025, 9, 10)
    db_path = compute_partition_path(str(db_base), date)
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(
            """
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS servers (
              server_id TEXT PRIMARY KEY,
              hostname TEXT,
              env TEXT,
              first_seen_ts INTEGER
            );
            CREATE TABLE IF NOT EXISTS requests (
              request_id TEXT PRIMARY KEY,
              server_id TEXT NOT NULL,
              ts INTEGER NOT NULL,
              endpoint TEXT NOT NULL,
              model_original TEXT,
              model_mapped TEXT,
              status_code INTEGER,
              latency_ms REAL,
              api_key_hash TEXT,
              request_json TEXT NOT NULL,
              response_json TEXT NOT NULL,
              dialog_id TEXT
            );
            """
        )
        req_json = '{"messages": [{"role": "user", "content": "Hello"}]}'
        resp_json = (
            '{"choices": [{"message": {"role": "assistant", "content": "Hi there"}}]}'
        )
        conn.execute(
            "INSERT OR REPLACE INTO requests (request_id, server_id, ts, endpoint, model_original, model_mapped, status_code, latency_ms, api_key_hash, request_json, response_json, dialog_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,NULL)",
            (
                "req1",
                "srv1",
                int(dt.datetime(2025, 9, 10, 12, 0).timestamp()),
                "/v1/chat/completions",
                "gpt-4",
                "openrouter/openai/gpt-4",
                200,
                123.4,
                None,
                req_json,
                resp_json,
            ),
        )
        conn.commit()
    finally:
        conn.close()
    return db_path
