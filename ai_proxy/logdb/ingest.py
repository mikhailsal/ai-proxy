import argparse
import datetime as dt
import hashlib
import json
import os
import socket
import sqlite3
import uuid
from dataclasses import dataclass
from typing import Dict, Iterator, List, Optional, Tuple

from .partitioning import ensure_partition_database, ensure_control_database
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


def _derive_server_id(base_db_dir: Optional[str] = None) -> str:
    """Derive a stable server id and persist it once per host.

    Resolution order (Stage C):
    1) LOGDB_SERVER_ID env var (explicit override)
    2) .server_id file under base_db_dir (if provided)
    3) Create and persist a new UUID4 into .server_id (if base_db_dir provided)
    4) Fallback: deterministic UUID5 from hostname+env
    """
    # Explicit override is highest priority
    explicit = os.getenv("LOGDB_SERVER_ID")
    if explicit:
        return explicit.strip()

    server_file_path = None
    if base_db_dir:
        try:
            server_file_path = os.path.join(os.path.abspath(base_db_dir), ".server_id")
            # Read if exists
            if os.path.isfile(server_file_path):
                with open(server_file_path, "r", encoding="utf-8") as f:
                    sid = f.read().strip()
                    if sid:
                        return sid
        except Exception:
            # Non-fatal: fall through to generation
            server_file_path = None

    # Generate a new id
    if server_file_path:
        try:
            os.makedirs(os.path.dirname(server_file_path), exist_ok=True)
            new_id = str(uuid.uuid4())
            with open(server_file_path, "w", encoding="utf-8") as f:
                f.write(new_id)
            return new_id
        except Exception:
            pass

    # Last resort: deterministic based on hostname and env
    env = os.getenv("LOGDB_ENV") or os.getenv("ENV") or "dev"
    hostname = socket.gethostname()
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


def _file_prefix_sha256(path: str, upto_bytes: int) -> str:
    h = hashlib.sha256()
    read_left = max(0, int(upto_bytes))
    with open(path, "rb") as f:
        while read_left > 0:
            chunk = f.read(min(65536, read_left))
            if not chunk:
                break
            h.update(chunk)
            read_left -= len(chunk)
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
) -> Tuple[int, int, Optional[str]]:
    cur = conn.execute(
        "SELECT bytes_ingested, mtime FROM ingest_sources WHERE source_path= ?",
        (source_path,),
    )
    row = cur.fetchone()
    if not row:
        return 0, 0, None
    # bytes_ingested, mtime, sha256
    cur2 = conn.execute(
        "SELECT sha256 FROM ingest_sources WHERE source_path= ?",
        (source_path,),
    )
    row2 = cur2.fetchone()
    return int(row[0] or 0), int(row[1] or 0), (row2[0] if row2 and row2[0] else None)


def _estimate_batch_bytes(batch: List[Tuple]) -> int:
    total = 0
    for row in batch:
        # request_json at index -2, response_json at index -1 for our tuple shape
        try:
            req = row[-2]
            resp = row[-1]
            total += len(req.encode("utf-8")) + len(resp.encode("utf-8"))
        except Exception:
            total += 0
    # include some overhead per row
    total += len(batch) * 128
    return total


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)).strip())
    except Exception:
        return default


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

    # Use dedicated control DB for checkpoints and server registry
    control_db = ensure_control_database(base_db_dir)
    conn = open_connection_with_pragmas(control_db)
    try:
        _ensure_servers_row(conn, server_id)

        # Determine resume offset
        prev_bytes, prev_mtime, prev_sha = _read_checkpoint(conn, source_path)
        stat = os.stat(source_path)
        start_pos = 0
        if prev_bytes > 0 and prev_bytes <= stat.st_size:
            try:
                # Validate prefix SHA to ensure file was not rewritten
                current_prefix_sha = _file_prefix_sha256(source_path, prev_bytes)
                if prev_sha and current_prefix_sha == prev_sha:
                    start_pos = prev_bytes
            except Exception:
                start_pos = 0

        with open(source_path, "r", encoding="utf-8", errors="ignore") as f:
            if start_pos:
                # Seek to resume position. If we are at a line boundary, do not drop the next line.
                # If we are in the middle of a line, drop the remainder of that line.
                if start_pos > 0:
                    f.seek(start_pos - 1)
                    prev_char = f.read(1)
                    if prev_char == "\n":
                        f.seek(start_pos)
                    else:
                        f.seek(start_pos)
                        f.readline()
                else:
                    f.seek(start_pos)

            last_good_pos = f.tell()
            # Prepare per-partition batch buffers and connections
            conns: Dict[str, sqlite3.Connection] = {}
            batches: Dict[
                str,
                List[
                    Tuple[
                        str,
                        str,
                        int,
                        str,
                        Optional[str],
                        Optional[str],
                        Optional[int],
                        Optional[float],
                        Optional[str],
                        str,
                        str,
                    ]
                ],
            ] = {}

            # Stage I: resource caps
            max_rows_per_batch = max(1, _env_int("LOGDB_BATCH_ROWS", 500))
            max_batch_bytes = max(0, _env_int("LOGDB_BATCH_KB", 1024) * 1024)
            max_memory_bytes = max(0, _env_int("LOGDB_MEMORY_MB", 256) * 1024 * 1024)

            def _flush(db_path: str) -> None:
                nonlocal inserted
                batch = batches.get(db_path)
                if not batch:
                    return
                pc = conns[db_path]
                before = pc.total_changes
                with pc:
                    pc.executemany(
                        """
                        INSERT OR IGNORE INTO requests (
                          request_id, server_id, ts, endpoint, model_original, model_mapped,
                          status_code, latency_ms, api_key_hash, request_json, response_json, dialog_id
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
                        """,
                        batch,
                    )
                after = pc.total_changes
                inserted += max(0, after - before)
                batches[db_path] = []

            def _current_memory_pressure() -> int:
                # Approximate current queued memory from batches
                total = 0
                for b in batches.values():
                    if b:
                        total += _estimate_batch_bytes(b)
                return total

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
                db_path = ensure_partition_database(
                    base_db_dir, norm["date"]
                )  # creates schema if needed
                if db_path not in conns:
                    conns[db_path] = open_connection_with_pragmas(db_path)
                    _ensure_servers_row(conns[db_path], server_id)
                    batches[db_path] = []

                request_id = _compute_request_id(server_id, norm)
                batches[db_path].append(
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
                    )
                )
                # Flush if rows threshold exceeded
                if len(batches[db_path]) >= max_rows_per_batch:
                    _flush(db_path)
                else:
                    # Flush if bytes threshold exceeded
                    if (
                        max_batch_bytes > 0
                        and _estimate_batch_bytes(batches[db_path]) >= max_batch_bytes
                    ):
                        _flush(db_path)
                # Global memory pressure: flush all if over cap
                if (
                    max_memory_bytes > 0
                    and _current_memory_pressure() >= max_memory_bytes
                ):
                    for pth in list(batches.keys()):
                        _flush(pth)

                last_good_pos = end_pos

            # Flush all remaining batches and close connections
            for path, _ in list(batches.items()):
                _flush(path)
            for pc in conns.values():
                pc.close()

            # Update checkpoint at last complete block boundary with prefix sha
            # Compute sha of file prefix up to last_good_pos for robust resume
            file_prefix_sha = _file_prefix_sha256(source_path, last_good_pos)
            _upsert_ingest_checkpoint(
                conn, source_path, file_prefix_sha, last_good_pos, int(stat.st_mtime)
            )

    finally:
        conn.close()

    return inserted, skipped


def ingest_logs(
    source_dir: str,
    base_db_dir: str,
    since: Optional[dt.date] = None,
    to: Optional[dt.date] = None,
) -> IngestStats:
    server_id = _derive_server_id(base_db_dir)
    files: List[str] = []
    for root, _dirs, filenames in os.walk(source_dir):
        for name in filenames:
            # Accept rotated files too: *.log, *.log.1, *.log.20250910, etc.
            if not (name.endswith(".log") or ".log." in name):
                continue
            files.append(os.path.join(root, name))

    files_scanned = 0
    files_ingested = 0
    total_inserted = 0
    total_skipped = 0

    # Parallel ingestion
    try:
        from concurrent.futures import ThreadPoolExecutor, as_completed
    except Exception:
        ThreadPoolExecutor = None  # type: ignore

    max_workers_env = os.getenv("LOGDB_IMPORT_PARALLELISM", "2").strip()
    try:
        max_workers = max(1, int(max_workers_env))
    except Exception:
        max_workers = 2

    import time

    t_start = time.perf_counter()

    if ThreadPoolExecutor and max_workers > 1:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {}
            for path in sorted(files):
                files_scanned += 1
                futures[
                    executor.submit(
                        _scan_log_file, path, base_db_dir, since, to, server_id
                    )
                ] = path
            for fut in as_completed(futures):
                try:
                    inserted, skipped = fut.result()
                except sqlite3.OperationalError:
                    # In case of lock contention, fall back to single-thread for this file
                    p = futures[fut]
                    inserted, skipped = _scan_log_file(
                        p, base_db_dir, since, to, server_id
                    )
                if inserted or skipped:
                    files_ingested += 1
                total_inserted += inserted
                total_skipped += skipped
    else:
        for path in sorted(files):
            files_scanned += 1
            inserted, skipped = _scan_log_file(path, base_db_dir, since, to, server_id)
            if inserted or skipped:
                files_ingested += 1
            total_inserted += inserted
            total_skipped += skipped

    elapsed_s = max(0.000001, time.perf_counter() - t_start)
    rows_per_sec = float(total_inserted) / elapsed_s
    # Emit concise performance line for operators (stdout). Kept simple for tests.
    print(
        f"ingest_elapsed_s={elapsed_s:.3f} rows_inserted={total_inserted} rps={rows_per_sec:.1f}"
    )

    return IngestStats(
        files_scanned=files_scanned,
        files_ingested=files_ingested,
        rows_inserted=total_inserted,
        rows_skipped=total_skipped,
    )


def add_cli(subparsers) -> None:
    p = subparsers.add_parser(
        "ingest", help="Ingest structured logs into SQLite partitions"
    )
    p.add_argument(
        "--from",
        dest="source",
        required=False,
        default="logs/",
        help="Source logs directory",
    )
    p.add_argument(
        "--out",
        dest="out",
        required=False,
        default="logs/db",
        help="Base directory for DB partitions",
    )
    p.add_argument(
        "--since", dest="since", required=False, help="Start date YYYY-MM-DD"
    )
    p.add_argument("--to", dest="to", required=False, help="End date YYYY-MM-DD")

    def _cmd(args: argparse.Namespace) -> int:
        # Feature flag gate: importer is controlled by LOGDB_ENABLED (tooling-only)
        if os.getenv("LOGDB_ENABLED", "false").lower() != "true":
            print("Ingest disabled by LOGDB_ENABLED")
            return 2
        since_date = (
            dt.datetime.strptime(args.since, "%Y-%m-%d").date() if args.since else None
        )
        to_date = dt.datetime.strptime(args.to, "%Y-%m-%d").date() if args.to else None
        stats = ingest_logs(args.source, args.out, since_date, to_date)
        print(
            json.dumps(
                {
                    "files_scanned": stats.files_scanned,
                    "files_ingested": stats.files_ingested,
                    "rows_inserted": stats.rows_inserted,
                    "rows_skipped": stats.rows_skipped,
                },
                ensure_ascii=False,
            )
        )
        return 0

    p.set_defaults(func=_cmd)
