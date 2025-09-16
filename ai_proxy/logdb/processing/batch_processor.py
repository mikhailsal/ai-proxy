import datetime as dt
import hashlib
import os
import sqlite3
from typing import Dict, List, Optional, Tuple

from ..partitioning import ensure_partition_database, ensure_control_database
from ..parsers.log_parser import _iter_json_blocks, _parse_log_entry, _normalize_entry
from ..schema import open_connection_with_pragmas
from ..utils.checkpoint import _read_checkpoint, _upsert_ingest_checkpoint
from ..utils.file_utils import _file_prefix_sha256, _env_int
from ..utils.server_utils import _ensure_servers_row


def _compute_request_id(server_id: str, norm: Dict) -> str:
    req_sha = hashlib.sha256(norm["request_json"].encode("utf-8")).hexdigest()
    resp_sha = hashlib.sha256(norm["response_json"].encode("utf-8")).hexdigest()
    key = f"{server_id}|{norm['ts_iso']}|{norm['endpoint']}|{req_sha}|{resp_sha}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


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
