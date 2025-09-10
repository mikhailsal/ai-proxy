import datetime as dt
import json
import os
import sqlite3

from ai_proxy.logdb.fts import _extract_text_fragments, build_partition_fts
from ai_proxy.logdb.partitioning import ensure_partition_database
from ai_proxy.logdb.schema import open_connection_with_pragmas


def test_extract_text_fragments_various_shapes():
    req = {
        "messages": [
            {"role": "user", "content": "Hello"},
            {"role": "assistant", "content": [{"type": "text", "text": "How can I help?"}]},
        ],
        "prompt": "Extra prompt",
        "contents": [
            {"parts": [{"text": "Gemini style user text"}]}
        ],
    }

    resp = {
        "choices": [
            {"message": {"content": "Sure, here is info."}},
            {"message": {"content": [{"text": "Part A"}, {"text": "Part B"}]}}
        ],
        "candidates": [
            {"content": {"parts": [{"text": "Gemini answer"}]}}
        ],
        "content": "Top-level content"
    }

    frags = _extract_text_fragments(json.dumps(req), json.dumps(resp))
    texts = {(role, text) for role, text in frags}

    assert ("user", "Hello") in texts
    assert ("assistant", "How can I help?") in texts
    assert ("user", "Extra prompt") in texts
    assert ("user", "Gemini style user text") in texts
    # Extractor may merge assistant fragments; accept either separate or combined
    has_sure = any(role == "assistant" and "Sure, here is info." in text for role, text in texts)
    has_parts = any(role == "assistant" and "Part A" in text and "Part B" in text for role, text in texts)
    assert has_sure and has_parts
    assert ("assistant", "Gemini answer") in texts
    assert ("assistant", "Top-level content") in texts


def test_build_partition_fts_and_query(tmp_path):
    base = tmp_path / "logs" / "db"
    date = dt.date(2025, 1, 2)
    db_path = ensure_partition_database(str(base), date)

    conn = open_connection_with_pragmas(db_path)
    try:
        req1 = {
            "messages": [
                {"role": "user", "content": "Please retry after timeout"}
            ]
        }
        resp1 = {
            "choices": [
                {"message": {"content": "Acknowledged, performing retry"}}
            ]
        }

        req2 = {"prompt": "Model parameters info"}
        resp2 = {"content": "Assistant description of model"}

        with conn:
            conn.execute(
                """
                INSERT INTO requests (
                  request_id, server_id, ts, endpoint, model_original, model_mapped,
                  status_code, latency_ms, api_key_hash, request_json, response_json, dialog_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
                """,
                (
                    "r1", "s1", int(dt.datetime(2025,1,2,12,0,0).timestamp()), "/v1/chat", "mA", "mB",
                    200, 12.5, None, json.dumps(req1), json.dumps(resp1)
                ),
            )
            conn.execute(
                """
                INSERT INTO requests (
                  request_id, server_id, ts, endpoint, model_original, model_mapped,
                  status_code, latency_ms, api_key_hash, request_json, response_json, dialog_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
                """,
                (
                    "r2", "s1", int(dt.datetime(2025,1,2,12,1,0).timestamp()), "/v1/chat", None, None,
                    200, 8.0, None, json.dumps(req2), json.dumps(resp2)
                ),
            )

        rows_indexed, rows_skipped = build_partition_fts(db_path)
        assert rows_indexed >= 3
        assert rows_skipped >= 0

        # Validate presence and ability to search
        cur = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='request_text_index'"
        )
        assert cur.fetchone() is not None

        q = "SELECT COUNT(*) FROM request_text_index WHERE request_text_index MATCH ?"
        timeout_hits = conn.execute(q, ("timeout",)).fetchone()[0]
        retry_hits = conn.execute(q, ("retry",)).fetchone()[0]
        model_hits = conn.execute(q, ("model",)).fetchone()[0]
        assert timeout_hits >= 1
        assert retry_hits >= 1
        assert model_hits >= 1

        # Join back to requests
        join_cnt = conn.execute(
            "SELECT COUNT(*) FROM request_text_index r JOIN requests q ON q.request_id=r.request_id"
        ).fetchone()[0]
        assert join_cnt >= rows_indexed
    finally:
        conn.close()


