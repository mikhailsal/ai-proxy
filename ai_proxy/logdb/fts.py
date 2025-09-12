import datetime as dt
import json
import os
import sqlite3
from typing import Iterable, List, Optional, Tuple

from .partitioning import compute_partition_path
from .schema import open_connection_with_pragmas


def _sqlite_supports_fts5(conn: sqlite3.Connection) -> bool:
    try:
        cur = conn.execute(
            "SELECT 1 FROM pragma_compile_options WHERE compile_options LIKE 'FTS5%';"
        )
        row = cur.fetchone()
        if row:
            return True
        # Fallback attempt: try creating a temp fts5 table
        try:
            conn.execute(
                "CREATE VIRTUAL TABLE IF NOT EXISTS temp.__fts5_probe USING fts5(x);"
            )
            conn.execute("DROP TABLE IF EXISTS temp.__fts5_probe;")
            return True
        except sqlite3.OperationalError:
            return False
    except Exception:
        return False


def create_fts_table(conn: sqlite3.Connection) -> None:
    if not _sqlite_supports_fts5(conn):
        raise RuntimeError("SQLite build does not support FTS5")
    with conn:
        conn.execute(
            (
                "CREATE VIRTUAL TABLE IF NOT EXISTS request_text_index USING fts5("
                "  request_id UNINDEXED,"
                "  role,"
                "  content,"
                "  endpoint,"
                "  model_original,"
                "  model_mapped,"
                "  tokenize='unicode61'"
                ");"
            )
        )


def drop_fts_table(conn: sqlite3.Connection) -> None:
    with conn:
        conn.execute("DROP TABLE IF EXISTS request_text_index;")


def _iter_text_from_messages(messages: object) -> Iterable[Tuple[str, str]]:
    if not isinstance(messages, list):
        return []
    out: List[Tuple[str, str]] = []
    for msg in messages:
        if not isinstance(msg, dict):
            continue
        role = str(msg.get("role")) if msg.get("role") is not None else "user"
        content = msg.get("content")
        # Content can be string or a list of parts
        if isinstance(content, str):
            text = content.strip()
            if text:
                out.append((role, text))
        elif isinstance(content, list):
            parts: List[str] = []
            for part in content:
                if isinstance(part, dict):
                    # Common shapes: {type: 'text', text: '...'} or {text: '...'}
                    t = part.get("text")
                    if isinstance(t, str) and t.strip():
                        parts.append(t.strip())
            joined = "\n".join(p for p in parts if p)
            if joined.strip():
                out.append((role, joined.strip()))
    return out


def _iter_text_from_response(resp: object) -> Iterable[Tuple[str, str]]:
    # Try OpenAI-like: choices[...].message.content
    try:
        if isinstance(resp, dict):
            choices = resp.get("choices")
            if isinstance(choices, list):
                texts: List[str] = []
                for ch in choices:
                    if not isinstance(ch, dict):
                        continue
                    msg = ch.get("message") or {}
                    content = msg.get("content") if isinstance(msg, dict) else None
                    if isinstance(content, str) and content.strip():
                        texts.append(content.strip())
                    elif isinstance(content, list):
                        parts: List[str] = []
                        for part in content:
                            if isinstance(part, dict):
                                t = part.get("text")
                                if isinstance(t, str) and t.strip():
                                    parts.append(t.strip())
                        if parts:
                            texts.append("\n".join(parts))
                if texts:
                    yield ("assistant", "\n\n".join(texts))
                # Some providers put text under 'content'
            primary = resp.get("content")
            if isinstance(primary, str) and primary.strip():
                yield ("assistant", primary.strip())
            # Gemini-like: candidates[0].content.parts[].text
            candidates = resp.get("candidates")
            if isinstance(candidates, list) and candidates:
                parts_candidate = (
                    candidates[0].get("content", {}).get("parts")
                    if isinstance(candidates[0], dict)
                    else None
                )
                if not isinstance(parts_candidate, list):
                    return
                texts_candidate: List[str] = []
                for p in parts_candidate:
                    if isinstance(p, dict):
                        t = p.get("text")
                        if isinstance(t, str) and t.strip():
                            texts_candidate.append(t.strip())
                if texts_candidate:
                    yield ("assistant", "\n".join(texts_candidate))
    except Exception:
        # If anything goes wrong, yield nothing
        return


def _extract_text_fragments(
    request_json: str, response_json: str
) -> List[Tuple[str, str]]:
    frags: List[Tuple[str, str]] = []
    try:
        req_obj = json.loads(request_json)
    except Exception:
        req_obj = None
    try:
        resp_obj = json.loads(response_json)
    except Exception:
        resp_obj = None

    if isinstance(req_obj, dict):
        msgs = req_obj.get("messages")
        for role, text in _iter_text_from_messages(msgs):
            if text:
                frags.append((role, text))

        # Also consider single-prompt shapes like {prompt: "..."}
        prompt = req_obj.get("prompt")
        if isinstance(prompt, str) and prompt.strip():
            frags.append(("user", prompt.strip()))

        # Google Gemini-like: contents[].parts[].text
        contents = req_obj.get("contents")
        if isinstance(contents, list):
            for c in contents:
                if not isinstance(c, dict):
                    continue
                parts = c.get("parts")
                if isinstance(parts, list):
                    texts: List[str] = []
                    for p in parts:
                        if isinstance(p, dict):
                            t = p.get("text")
                            if isinstance(t, str) and t.strip():
                                texts.append(t.strip())
                    if texts:
                        frags.append(("user", "\n".join(texts)))

    if isinstance(resp_obj, (dict, list)):
        for role, text in _iter_text_from_response(resp_obj):
            if text:
                frags.append((role, text))

    # Deduplicate identical fragments for the same role to reduce size
    seen = set()
    uniq: List[Tuple[str, str]] = []
    for role, text in frags:
        key = (role, text)
        if key in seen:
            continue
        seen.add(key)
        uniq.append((role, text))
    return uniq


def build_partition_fts(db_path: str) -> Tuple[int, int]:
    """Create FTS table and populate from requests in a single partition.

    Returns (rows_indexed, rows_skipped)
    """
    conn = open_connection_with_pragmas(db_path)
    try:
        if not _sqlite_supports_fts5(conn):
            raise RuntimeError("SQLite build does not support FTS5")
        drop_fts_table(conn)
        create_fts_table(conn)

        rows_indexed = 0
        rows_skipped = 0
        cur = conn.execute(
            "SELECT request_id, endpoint, model_original, model_mapped, request_json, response_json FROM requests"
        )
        batch: List[Tuple[str, str, str, str, str, str]] = []
        for (
            request_id,
            endpoint,
            model_original,
            model_mapped,
            req_json,
            resp_json,
        ) in cur:
            fragments = _extract_text_fragments(req_json or "", resp_json or "")
            if not fragments:
                rows_skipped += 1
                continue
            for role, content in fragments:
                content_str = (content or "").strip()
                if not content_str:
                    continue
                # Apply a soft cap to avoid pathological rows
                if len(content_str) > 20000:
                    content_str = content_str[:20000]
                batch.append(
                    (
                        request_id,
                        role or "user",
                        content_str,
                        endpoint or "",
                        model_original or "",
                        model_mapped or "",
                    )
                )
                if len(batch) >= 500:
                    with conn:
                        conn.executemany(
                            "INSERT INTO request_text_index (request_id, role, content, endpoint, model_original, model_mapped) VALUES (?, ?, ?, ?, ?, ?)",
                            batch,
                        )
                    rows_indexed += len(batch)
                    batch.clear()
        if batch:
            with conn:
                conn.executemany(
                    "INSERT INTO request_text_index (request_id, role, content, endpoint, model_original, model_mapped) VALUES (?, ?, ?, ?, ?, ?)",
                    batch,
                )
            rows_indexed += len(batch)

        # Optional: optimize
        with conn:
            conn.execute(
                "INSERT INTO request_text_index(request_text_index) VALUES('optimize');"
            )

        return rows_indexed, rows_skipped
    finally:
        conn.close()


def build_fts_for_range(
    base_db_dir: str, since: Optional[dt.date], to: Optional[dt.date]
) -> List[Tuple[str, int, int]]:
    """Build FTS for each partition between dates inclusive. Returns list of tuples
    (db_path, rows_indexed, rows_skipped) for partitions that existed and were processed.
    """
    if since is None and to is None:
        # Default: today only
        since = to = dt.date.today()
    if since is None and to is not None:
        since = to
    if to is None and since is not None:
        to = since
    assert since is not None and to is not None

    results: List[Tuple[str, int, int]] = []
    # De-duplicate DB paths to support weekly granularity
    unique_paths: List[str] = []
    cur_date = since
    while cur_date <= to:  # type: ignore[operator]
        db_path = compute_partition_path(base_db_dir, cur_date)
        if db_path not in unique_paths:
            unique_paths.append(db_path)
        cur_date = cur_date + dt.timedelta(days=1)

    for path in unique_paths:
        if os.path.isfile(path):
            rows_indexed, rows_skipped = build_partition_fts(path)
            results.append((path, rows_indexed, rows_skipped))
    return results


__all__ = [
    "create_fts_table",
    "drop_fts_table",
    "build_partition_fts",
    "build_fts_for_range",
]
