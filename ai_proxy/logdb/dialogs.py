import datetime as dt
import hashlib
import os
import sqlite3
from typing import Dict, List, Optional, Sequence, Tuple

from .partitioning import compute_partition_path
from .schema import open_connection_with_pragmas


def _parse_window_to_seconds(window: str) -> int:
    s = (window or "30m").strip().lower()
    if s.endswith("ms"):
        # Not supported, round up to 1 second
        return 1
    if s.endswith("s"):
        try:
            return max(1, int(s[:-1]))
        except Exception:
            return 1800
    if s.endswith("m"):
        try:
            return max(1, int(s[:-1]) * 60)
        except Exception:
            return 1800
    if s.endswith("h"):
        try:
            return max(1, int(s[:-1]) * 3600)
        except Exception:
            return 1800
    # Fallback: raw integer seconds if parsable
    try:
        return max(1, int(s))
    except Exception:
        return 1800


def _stable_dialog_id(api_key_hash: Optional[str], endpoint: Optional[str], model_mapped: Optional[str], first_ts: int) -> str:
    key = f"{api_key_hash or ''}|{endpoint or ''}|{model_mapped or ''}|{first_ts}"
    h = hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
    return f"dlg-{h}"


def assign_partition_dialogs(db_path: str, window_seconds: int) -> int:
    """Assign dialog_id for rows in a single partition database.

    Groups are defined by (api_key_hash, endpoint, model_mapped). Within each
    group, rows are ordered by timestamp (ts). A new dialog starts when the gap
    to the previous row exceeds the configured window.

    Returns number of rows updated (set/changed dialog_id).
    """
    conn = open_connection_with_pragmas(db_path)
    try:
        cur = conn.execute(
            """
            SELECT request_id, ts, endpoint, model_mapped, model_original, api_key_hash, dialog_id
            FROM requests
            ORDER BY COALESCE(api_key_hash, ''), COALESCE(endpoint, ''), COALESCE(model_mapped, ''), ts, request_id
            """
        )
        rows: List[Tuple[str, int, str, Optional[str], Optional[str], Optional[str], Optional[str]]] = list(cur.fetchall())

        updated: List[Tuple[str, str]] = []  # (dialog_id, request_id)

        last_ts_by_group: Dict[Tuple[str, str, str], int] = {}
        current_dialog_by_group: Dict[Tuple[str, str, str], str] = {}
        first_ts_of_current_by_group: Dict[Tuple[str, str, str], int] = {}

        for request_id, ts, endpoint, model_mapped, model_original, api_key_hash, existing_dialog in rows:
            key = (
                (api_key_hash or ""),
                (endpoint or ""),
                (model_mapped or ""),
            )
            last_ts = last_ts_by_group.get(key)
            if last_ts is None:
                # Start first dialog for this group
                first_ts = int(ts)
                dlg = _stable_dialog_id(key[0], key[1], key[2], first_ts)
                current_dialog_by_group[key] = dlg
                first_ts_of_current_by_group[key] = first_ts
                last_ts_by_group[key] = int(ts)
            else:
                # Continue or split based on time gap
                if int(ts) - int(last_ts) > window_seconds:
                    # New dialog starting at this ts
                    first_ts = int(ts)
                    dlg = _stable_dialog_id(key[0], key[1], key[2], first_ts)
                    current_dialog_by_group[key] = dlg
                    first_ts_of_current_by_group[key] = first_ts
                # Update last seen
                last_ts_by_group[key] = int(ts)

            target_dialog = current_dialog_by_group[key]
            if existing_dialog != target_dialog:
                updated.append((target_dialog, request_id))

        if updated:
            with conn:
                conn.executemany(
                    "UPDATE requests SET dialog_id=? WHERE request_id=?",
                    updated,
                )
        return len(updated)
    finally:
        conn.close()


def assign_dialogs_for_range(
    base_db_dir: str,
    since: Optional[dt.date],
    to: Optional[dt.date],
    window_seconds: int,
) -> List[Tuple[str, int]]:
    """Assign dialogs for each existing partition in [since, to].

    Returns list of (db_path, rows_updated) for processed partitions.
    """
    if since is None and to is None:
        since = to = dt.date.today()
    if since is None:
        since = to
    if to is None:
        to = since

    out: List[Tuple[str, int]] = []
    cur_date = since
    while cur_date <= to:  # type: ignore[operator]
        db_path = compute_partition_path(base_db_dir, cur_date)
        if os.path.isfile(db_path):
            updated = assign_partition_dialogs(db_path, window_seconds)
            out.append((db_path, updated))
        cur_date = cur_date + dt.timedelta(days=1)
    return out


__all__ = [
    "assign_partition_dialogs",
    "assign_dialogs_for_range",
    "_parse_window_to_seconds",
]


def clear_dialogs_for_range(
    base_db_dir: str,
    since: Optional[dt.date],
    to: Optional[dt.date],
) -> List[Tuple[str, int]]:
    """Clear dialog_id column for each existing partition in [since, to].

    Returns list of (db_path, rows_updated) for processed partitions.
    """
    if since is None and to is None:
        since = to = dt.date.today()
    if since is None:
        since = to
    if to is None:
        to = since

    out: List[Tuple[str, int]] = []
    cur_date = since
    while cur_date <= to:  # type: ignore[operator]
        db_path = compute_partition_path(base_db_dir, cur_date)
        if os.path.isfile(db_path):
            conn = open_connection_with_pragmas(db_path)
            try:
                with conn:
                    cur = conn.execute("UPDATE requests SET dialog_id=NULL WHERE dialog_id IS NOT NULL")
                out.append((db_path, cur.rowcount if cur is not None else 0))
            finally:
                conn.close()
        cur_date = cur_date + dt.timedelta(days=1)
    return out



