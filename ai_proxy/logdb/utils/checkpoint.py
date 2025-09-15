import datetime as dt
import sqlite3
import socket
import os


def _ensure_servers_row(conn: sqlite3.Connection, server_id: str) -> None:
    hostname = socket.gethostname()
    env = os.getenv("LOGDB_ENV") or os.getenv("ENV") or "dev"
    now = int(dt.datetime.utcnow().timestamp())
    with conn:
        conn.execute(
            """
            INSERT OR IGNORE INTO servers (server_id, hostname, env, first_seen_ts)
            VALUES (?, ?, ?, ?)
            """,
            (server_id, hostname, env, now),
        )


def _upsert_ingest_checkpoint(
    conn: sqlite3.Connection,
    source_path: str,
    sha256_hex: str,
    bytes_ingested: int,
    mtime: int,
) -> None:
    now = int(dt.datetime.utcnow().timestamp())
    with conn:
        conn.execute(
            """
            INSERT INTO ingest_sources (source_path, sha256, bytes_ingested, mtime, last_scan_ts)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(source_path) DO UPDATE SET
              sha256=excluded.sha256,
              bytes_ingested=excluded.bytes_ingested,
              mtime=excluded.mtime,
              last_scan_ts=excluded.last_scan_ts
            """,
            (source_path, sha256_hex, bytes_ingested, mtime, now),
        )


def _read_checkpoint(
    conn: sqlite3.Connection, source_path: str
) -> tuple[int, int, str | None]:
    cur = conn.execute(
        "SELECT bytes_ingested, mtime FROM ingest_sources WHERE source_path= ?",
        (source_path,),
    )
    row = cur.fetchone()
    if not row:
        return 0, 0, None
    cur2 = conn.execute(
        "SELECT sha256 FROM ingest_sources WHERE source_path= ?",
        (source_path,),
    )
    row2 = cur2.fetchone()
    return int(row[0] or 0), int(row[1] or 0), (row2[0] if row2 and row2[0] else None)

