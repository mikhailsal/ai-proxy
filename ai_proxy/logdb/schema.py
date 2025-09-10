import os
import sqlite3
from typing import Iterable, Optional


SCHEMA_DDL: str = """
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
CREATE TABLE IF NOT EXISTS ingest_sources (
  source_path TEXT PRIMARY KEY,
  sha256 TEXT,
  bytes_ingested INTEGER,
  mtime INTEGER,
  last_scan_ts INTEGER
);
CREATE INDEX IF NOT EXISTS idx_requests_ts ON requests(ts);
CREATE INDEX IF NOT EXISTS idx_requests_endpoint ON requests(endpoint);
CREATE INDEX IF NOT EXISTS idx_requests_status ON requests(status_code);
CREATE INDEX IF NOT EXISTS idx_requests_model_orig ON requests(model_original);
CREATE INDEX IF NOT EXISTS idx_requests_model_mapped ON requests(model_mapped);
CREATE INDEX IF NOT EXISTS idx_requests_api ON requests(api_key_hash);
""".strip()


def open_connection_with_pragmas(db_path: str) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    # Apply recommended pragmas for durability vs speed during batch ops
    with conn:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA busy_timeout=5000;")
        conn.execute("PRAGMA foreign_keys=ON;")
        # Optional: set WAL autocheckpoint pages to keep WAL bounded (Stage I)
        try:
            wal_autock = int(os.getenv("LOGDB_WAL_AUTOCHECKPOINT_PAGES", "1000").strip())
            wal_autock = max(0, wal_autock)
            conn.execute(f"PRAGMA wal_autocheckpoint={wal_autock};")
        except Exception:
            # Leave default if env invalid
            pass
        # Optional: cache size (negative means KB units)
        try:
            cache_kb = int(os.getenv("LOGDB_SQLITE_CACHE_KB", "0").strip())
            if cache_kb > 0:
                conn.execute(f"PRAGMA cache_size=-{cache_kb};")
        except Exception:
            pass
    return conn


def create_or_migrate_schema(conn: sqlite3.Connection) -> None:
    statements: Iterable[str] = (stmt.strip() for stmt in SCHEMA_DDL.split(";") if stmt.strip())
    with conn:
        for stmt in statements:
            conn.execute(stmt)


def run_integrity_check(conn: sqlite3.Connection) -> str:
    cur = conn.execute("PRAGMA integrity_check;")
    row = cur.fetchone()
    return row[0] if row else "unknown"


def ensure_schema(db_path: str) -> None:
    conn = open_connection_with_pragmas(db_path)
    try:
        create_or_migrate_schema(conn)
        # Switch to FULL after batch setup to prioritize durability when used interactively
        with conn:
            conn.execute("PRAGMA synchronous=FULL;")
    finally:
        conn.close()



