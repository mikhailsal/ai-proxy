import os
import sqlite3
from typing import Iterable, List, Tuple

from .schema import ensure_schema, run_integrity_check


def _find_partition_files(source_dir: str) -> List[str]:
    out: List[str] = []
    base = os.path.abspath(source_dir)
    for root, _dirs, names in os.walk(base):
        for n in names:
            if n.endswith(".sqlite3"):
                out.append(os.path.join(root, n))
    return sorted(out)


def merge_partitions(source_dir: str, dest_path: str) -> Tuple[int, int, str]:
    """Merge all partition databases under source_dir into a single dest_path.

    Performs INSERT OR IGNORE into destination tables for idempotent merging.

    Returns (num_sources, total_requests_after_merge, integrity_status).
    """
    files = _find_partition_files(source_dir)
    os.makedirs(os.path.dirname(os.path.abspath(dest_path)) or ".", exist_ok=True)

    # Ensure destination schema exists
    ensure_schema(dest_path)

    conn = sqlite3.connect(dest_path)
    try:
        for idx, src in enumerate(files):
            alias = f"src{idx}"
            conn.execute(f"ATTACH DATABASE ? AS {alias}", (src,))
            try:
                with conn:
                    # Order: servers then requests then ingest_sources
                    conn.execute(
                        f"INSERT OR IGNORE INTO main.servers SELECT * FROM {alias}.servers"
                    )
                    conn.execute(
                        f"INSERT OR IGNORE INTO main.requests SELECT * FROM {alias}.requests"
                    )
                    conn.execute(
                        f"INSERT OR IGNORE INTO main.ingest_sources SELECT * FROM {alias}.ingest_sources"
                    )
            finally:
                conn.execute(f"DETACH DATABASE {alias}")

        cur = conn.execute("SELECT COUNT(*) FROM requests")
        total_requests = int(cur.fetchone()[0])
        status = run_integrity_check(conn)
        return len(files), total_requests, status
    finally:
        conn.close()


def merge_partitions_from_files(
    source_files: Iterable[str], dest_path: str
) -> Tuple[int, int, str]:
    """Merge specific partition database files into a single destination.

    This is similar to merge_partitions but takes an explicit iterable of file paths.
    It performs INSERT OR IGNORE, is idempotent, and returns the same tuple as
    merge_partitions: (num_sources, total_requests_after_merge, integrity_status).
    """
    files = sorted({os.path.abspath(p) for p in source_files if os.path.isfile(p)})
    os.makedirs(os.path.dirname(os.path.abspath(dest_path)) or ".", exist_ok=True)

    ensure_schema(dest_path)

    conn = sqlite3.connect(dest_path)
    try:
        for idx, src in enumerate(files):
            alias = f"src{idx}"
            conn.execute(f"ATTACH DATABASE ? AS {alias}", (src,))
            try:
                with conn:
                    conn.execute(
                        f"INSERT OR IGNORE INTO main.servers SELECT * FROM {alias}.servers"
                    )
                    conn.execute(
                        f"INSERT OR IGNORE INTO main.requests SELECT * FROM {alias}.requests"
                    )
                    conn.execute(
                        f"INSERT OR IGNORE INTO main.ingest_sources SELECT * FROM {alias}.ingest_sources"
                    )
            finally:
                conn.execute(f"DETACH DATABASE {alias}")

        cur = conn.execute("SELECT COUNT(*) FROM requests")
        total_requests = int(cur.fetchone()[0])
        status = run_integrity_check(conn)
        return len(files), total_requests, status
    finally:
        conn.close()
