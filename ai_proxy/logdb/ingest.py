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

# Extracted helpers
from .parsers.log_parser import (
    _safe_iso_to_datetime,
    _iter_json_blocks,
    _parse_log_entry,
    _normalize_entry,
    _compute_request_id,
)
from .utils.file_utils import (
    _derive_server_id,
    _file_sha256,
    _file_prefix_sha256,
    _env_int,
)
from .utils.checkpoint import (
    _ensure_servers_row,
    _upsert_ingest_checkpoint,
    _read_checkpoint,
)
from .processing.batch_processor import _scan_log_file, _estimate_batch_bytes


@dataclass(frozen=True)
class IngestStats:
    files_scanned: int
    files_ingested: int
    rows_inserted: int
    rows_skipped: int



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

        has_parallel = True
    except Exception:
        has_parallel = False

    max_workers_env = os.getenv("LOGDB_IMPORT_PARALLELISM", "2").strip()
    try:
        max_workers = max(1, int(max_workers_env))
    except Exception:
        max_workers = 2

    import time

    t_start = time.perf_counter()

    if has_parallel and max_workers > 1:
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
