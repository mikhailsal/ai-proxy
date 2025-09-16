# Helper utilities used by split UI tests


def _make_partition(db_path: str, rows: int, base_ts: int, start_id: int = 0):
    import sqlite3
    import os as _os

    _os.makedirs(_os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(
            """
            PRAGMA journal_mode=WAL;
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
        with conn:
            for i in range(rows):
                rid = f"t{start_id + i:04d}"
                conn.execute(
                    "INSERT OR IGNORE INTO requests(request_id, server_id, ts, endpoint, model_original, model_mapped, status_code, latency_ms, api_key_hash, request_json, response_json, dialog_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,NULL)",
                    (
                        rid,
                        "srv-1",
                        base_ts + i,
                        "/v1/chat/completions",
                        "m",
                        "m",
                        200,
                        12.5,
                        "k",
                        "{}",
                        "{}",
                    ),
                )
    finally:
        conn.close()
