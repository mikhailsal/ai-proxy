import argparse
import datetime as dt
import hashlib
import json
import os
import socket
import sqlite3
import uuid
from dataclasses import dataclass
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

from .partitioning import ensure_partition_database
from .schema import open_connection_with_pragmas


@dataclass(frozen=True)
class IngestStats:
    files_scanned: int
    files_ingested: int
    rows_inserted: int
    rows_skipped: int


def _safe_iso_to_datetime(ts: str) -> Optional[dt.datetime]:
    if not ts:
        return None
    try:
        # Accept timestamps like 2025-06-26T08:42:42.753538Z
        if ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        return dt.datetime.fromisoformat(ts)
    except Exception:
        return None


def _derive_server_id() -> str:
    """Derive a stable server id based on hostname and env.

    Stage C will formalize this, but Stage B needs a stable, non-null value.
    """
    env = os.getenv("LOGDB_ENV") or os.getenv("ENV") or "dev"
    hostname = socket.gethostname()
    # Deterministic UUID5 to remain stable across runs
    server_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, f"ai-proxy|{hostname}|{env}")
    return str(server_uuid)


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


def _file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _iter_json_blocks(f) -> Iterator[Tuple[int, str]]:
    """Yield (block_end_pos, json_text) for each rendered JSON block in a log file.

    The log format is: "asctime - level - {\n  ... pretty json ...\n}"
    JSON can span multiple lines. We detect the first '{' and then
    track brace depth until it returns to zero.
    """
    buffer: Optional[List[str]] = None
    depth = 0
    while True:
        line = f.readline()
        if not line:
            # EOF
            if buffer is not None:
                # Incomplete trailing block; drop it safely
                buffer = None
                depth = 0
            break

        if buffer is None:
            brace_idx = line.find("{")
            if brace_idx == -1:
                continue
            buffer = [line[brace_idx:]]
            depth = buffer[-1].count("{") - buffer[-1].count("}")
            if depth == 0:
                json_text = "".join(buffer)
                buffer = None
                yield f.tell(), json_text
            continue

        # We are inside a JSON block
        buffer.append(line)
        depth += line.count("{") - line.count("}")
        if depth <= 0:
            json_text = "".join(buffer)
            buffer = None
            yield f.tell(), json_text


def _parse_log_entry(json_text: str) -> Optional[Dict]:
    try:
        entry = json.loads(json_text)
    except Exception:
        return None

    # Minimal required fields to consider this an API request/response entry
    if not isinstance(entry, dict):
        return None
    if "endpoint" not in entry or "request" not in entry or "response" not in entry:
        return None

    return entry


def _normalize_entry(entry: Dict) -> Optional[Dict]:
    ts_iso = entry.get("timestamp")
    dt_obj = _safe_iso_to_datetime(ts_iso)
    if dt_obj is None:
        return None
    if dt_obj.tzinfo is None:
        # Assume UTC if tz-naive
        dt_obj = dt_obj.replace(tzinfo=dt.timezone.utc)
    epoch_sec = int(dt_obj.timestamp())

    endpoint = str(entry.get("endpoint", ""))
    if not endpoint:
        return None

    request_obj = entry.get("request")
    response_obj = entry.get("response")
    if request_obj is None or response_obj is None:
        return None

    try:
        request_json = json.dumps(request_obj, ensure_ascii=False, sort_keys=True)
        response_json = json.dumps(response_obj, ensure_ascii=False, sort_keys=True)
    except Exception:
        return None

    model_original = None
    if isinstance(request_obj, dict):
        model_original = request_obj.get("model")
    model_mapped = None
    if isinstance(response_obj, dict):
        model_mapped = response_obj.get("model")

    # Be tolerant to noisy values
    status_code_val = entry.get("status_code")
    try:
        status_code = int(status_code_val) if status_code_val is not None else None
    except Exception:
        status_code = None

    latency_val = entry.get("latency_ms")
    try:
        latency_ms = float(latency_val) if latency_val is not None else None
    except Exception:
        latency_ms = None
    api_key_hash = entry.get("api_key_hash")

    return {
        "ts_iso": ts_iso,
        "epoch_sec": epoch_sec,
        "endpoint": endpoint,
        "model_original": model_original,
        "model_mapped": model_mapped,
        "status_code": status_code,
        "latency_ms": latency_ms,
        "api_key_hash": api_key_hash,
        "request_json": request_json,
        "response_json": response_json,
        "date": dt_obj.astimezone(dt.timezone.utc).date(),
    }


def _compute_request_id(server_id: str, norm: Dict) -> str:
    req_sha = hashlib.sha256(norm["request_json"].encode("utf-8")).hexdigest()
    resp_sha = hashlib.sha256(norm["response_json"].encode("utf-8")).hexdigest()
    key = f"{server_id}|{norm['ts_iso']}|{norm['endpoint']}|{req_sha}|{resp_sha}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def _upsert_ingest_checkpoint(conn: sqlite3.Connection, source_path: str, sha256_hex: str, bytes_ingested: int, mtime: int) -> None:
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


def _read_checkpoint(conn: sqlite3.Connection, source_path: str) -> Tuple[int, int]:
    cur = conn.execute(
        "SELECT bytes_ingested, mtime FROM ingest_sources WHERE source_path=?",
        (source_path,),
    )
    row = cur.fetchone()
    if not row:
        return 0, 0
    return int(row[0] or 0), int(row[1] or 0)


def _scan_log_file(
    source_path: str,
    base_db_dir: str,
    since: Optional[dt.date],
    to: Optional[dt.date],
    server_id: str,
) -> Tuple[int, int]:
    """Scan a single log file and ingest records into partitioned DBs.

    Returns (inserted_rows, skipped_rows).
    """
    inserted = 0
    skipped = 0

    # Open a temporary SQLite connection against a small control DB under base_db_dir to store checkpoints
    control_db = ensure_partition_database(base_db_dir, dt.date.today())
    conn = open_connection_with_pragmas(control_db)
    try:
        _ensure_servers_row(conn, server_id)

        # Determine resume offset
        prev_bytes, prev_mtime = _read_checkpoint(conn, source_path)
        stat = os.stat(source_path)
        start_pos = 0
        if prev_bytes > 0 and stat.st_mtime == prev_mtime and prev_bytes <= stat.st_size:
            start_pos = prev_bytes

        with open(source_path, "r", encoding="utf-8", errors="ignore") as f:
            if start_pos:
                f.seek(start_pos)
                # Best-effort resync: drop partial line, continue to next JSON block
                f.readline()

            last_good_pos = f.tell()
            for end_pos, json_text in _iter_json_blocks(f):
                entry = _parse_log_entry(json_text)
                if not entry:
                    last_good_pos = end_pos
                    continue

                norm = _normalize_entry(entry)
                if not norm:
                    skipped += 1
                    last_good_pos = end_pos
                    continue

                # Date range filter
                if since and norm["date"] < since:
                    last_good_pos = end_pos
                    continue
                if to and norm["date"] > to:
                    last_good_pos = end_pos
                    continue

                # Open partition DB for this record's date
                db_path = ensure_partition_database(base_db_dir, norm["date"])  # creates schema if needed
                part_conn = open_connection_with_pragmas(db_path)
                try:
                    _ensure_servers_row(part_conn, server_id)
                    request_id = _compute_request_id(server_id, norm)
                    with part_conn:
                        part_conn.execute(
                            """
                            INSERT OR IGNORE INTO requests (
                              request_id, server_id, ts, endpoint, model_original, model_mapped,
                              status_code, latency_ms, api_key_hash, request_json, response_json, dialog_id
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
                            """,
                            (
                                request_id,
                                server_id,
                                norm["epoch_sec"],
                                norm["endpoint"],
                                norm["model_original"],
                                norm["model_mapped"],
                                norm["status_code"],
                                norm["latency_ms"],
                                norm["api_key_hash"],
                                norm["request_json"],
                                norm["response_json"],
                            ),
                        )
                        inserted += part_conn.total_changes  # counts rows inserted by last statement
                finally:
                    part_conn.close()

                last_good_pos = end_pos

            # Update checkpoint at last complete block boundary
            file_sha = _file_sha256(source_path)
            _upsert_ingest_checkpoint(conn, source_path, file_sha, last_good_pos, int(stat.st_mtime))

    finally:
        conn.close()

    return inserted, skipped


def ingest_logs(
    source_dir: str,
    base_db_dir: str,
    since: Optional[dt.date] = None,
    to: Optional[dt.date] = None,
) -> IngestStats:
    server_id = _derive_server_id()
    files: List[str] = []
    for root, _dirs, filenames in os.walk(source_dir):
        for name in filenames:
            if not name.endswith(".log"):
                continue
            files.append(os.path.join(root, name))

    files_scanned = 0
    files_ingested = 0
    total_inserted = 0
    total_skipped = 0

    for path in sorted(files):
        files_scanned += 1
        inserted, skipped = _scan_log_file(path, base_db_dir, since, to, server_id)
        if inserted or skipped:
            files_ingested += 1
        total_inserted += inserted
        total_skipped += skipped

    return IngestStats(
        files_scanned=files_scanned,
        files_ingested=files_ingested,
        rows_inserted=total_inserted,
        rows_skipped=total_skipped,
    )


def add_cli(subparsers) -> None:
    p = subparsers.add_parser("ingest", help="Ingest structured logs into SQLite partitions")
    p.add_argument("--from", dest="source", required=False, default="logs/", help="Source logs directory")
    p.add_argument("--out", dest="out", required=False, default="logs/db", help="Base directory for DB partitions")
    p.add_argument("--since", dest="since", required=False, help="Start date YYYY-MM-DD")
    p.add_argument("--to", dest="to", required=False, help="End date YYYY-MM-DD")

    def _cmd(args: argparse.Namespace) -> int:
        since_date = dt.datetime.strptime(args.since, "%Y-%m-%d").date() if args.since else None
        to_date = dt.datetime.strptime(args.to, "%Y-%m-%d").date() if args.to else None
        stats = ingest_logs(args.source, args.out, since_date, to_date)
        print(json.dumps({
            "files_scanned": stats.files_scanned,
            "files_ingested": stats.files_ingested,
            "rows_inserted": stats.rows_inserted,
            "rows_skipped": stats.rows_skipped,
        }, ensure_ascii=False))
        return 0

    p.set_defaults(func=_cmd)


