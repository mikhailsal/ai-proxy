import json
import os
import sqlite3
import pytest
from unittest import mock

from ai_proxy.logdb.fts import (
    _sqlite_supports_fts5,
    create_fts_table,
    drop_fts_table,
    _iter_text_from_messages,
    _iter_text_from_response,
    _extract_text_fragments,
)
from ai_proxy.logdb.schema import open_connection_with_pragmas


@pytest.fixture
def temp_db_path(tmp_path):
    db_path = str(tmp_path / "test_fts.db")
    conn = open_connection_with_pragmas(db_path)
    conn.close()
    yield db_path
    if os.path.exists(db_path):
        os.remove(db_path)


# Tests for _sqlite_supports_fts5
def test_sqlite_supports_fts5_true_with_compile_option():
    mock_conn = mock.MagicMock()
    mock_cur = mock.Mock()
    mock_cur.fetchone.return_value = ("FTS5=1",)
    mock_conn.execute.return_value = mock_cur
    assert _sqlite_supports_fts5(mock_conn) is True


def test_sqlite_supports_fts5_true_with_table_creation():
    mock_conn = mock.MagicMock()
    mock_cur = mock.Mock()
    mock_cur.fetchone.return_value = None

    def side_effect(q):
        if "pragma_compile_options" in q:
            return mock_cur
        # Simulate success for CREATE/DROP
        return mock.Mock()

    mock_conn.execute.side_effect = side_effect
    assert _sqlite_supports_fts5(mock_conn) is True


def test_sqlite_supports_fts5_false_no_option_no_creation():
    mock_conn = mock.MagicMock()
    mock_cur = mock.Mock()
    mock_cur.fetchone.return_value = None

    def side_effect(q):
        if "pragma_compile_options" in q:
            return mock_cur
        if "CREATE" in q:
            raise sqlite3.OperationalError("no such module: fts5")
        return mock.Mock()

    mock_conn.execute.side_effect = side_effect
    assert _sqlite_supports_fts5(mock_conn) is False


def test_sqlite_supports_fts5_false_on_exception():
    mock_conn = mock.MagicMock()
    mock_conn.execute.side_effect = Exception("unexpected error")
    assert _sqlite_supports_fts5(mock_conn) is False


def test_sqlite_supports_fts5_false_on_creation_except():
    mock_conn = mock.MagicMock()
    mock_cur = mock.Mock()
    mock_cur.fetchone.return_value = None

    def side_effect(q):
        if "pragma_compile_options" in q:
            return mock_cur
        if "CREATE" in q:
            raise Exception("other error")
        return mock.Mock()

    mock_conn.execute.side_effect = side_effect
    assert _sqlite_supports_fts5(mock_conn) is False


# Tests for create_fts_table
def test_create_fts_table_success(temp_db_path):
    conn = open_connection_with_pragmas(temp_db_path)
    with mock.patch("ai_proxy.logdb.fts._sqlite_supports_fts5", return_value=True):
        create_fts_table(conn)
    table = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='request_text_index';"
    ).fetchone()
    assert table is not None


def test_create_fts_table_raises_if_no_fts5(temp_db_path):
    conn = open_connection_with_pragmas(temp_db_path)
    with (
        mock.patch("ai_proxy.logdb.fts._sqlite_supports_fts5", return_value=False),
        pytest.raises(RuntimeError, match="SQLite build does not support FTS5"),
    ):
        create_fts_table(conn)


# Tests for drop_fts_table
def test_drop_fts_table_success(temp_db_path):
    conn = open_connection_with_pragmas(temp_db_path)
    with mock.patch("ai_proxy.logdb.fts._sqlite_supports_fts5", return_value=True):
        create_fts_table(conn)
    drop_fts_table(conn)
    table = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='request_text_index';"
    ).fetchone()
    assert table is None


def test_drop_fts_table_noop_if_not_exists(temp_db_path):
    conn = open_connection_with_pragmas(temp_db_path)
    drop_fts_table(conn)  # Should not raise


# Tests for _iter_text_from_messages
def test_iter_text_from_messages_valid_list():
    messages = [
        {"role": "user", "content": "hello"},
        {"role": "assistant", "content": [{"type": "text", "text": "world"}]},
        {"role": "system", "content": [{"text": "test\nmulti"}]},
    ]
    result = list(_iter_text_from_messages(messages))
    assert result == [
        ("user", "hello"),
        ("assistant", "world"),
        ("system", "test\nmulti"),
    ]


def test_iter_text_from_messages_not_list():
    assert list(_iter_text_from_messages("not a list")) == []


def test_iter_text_from_messages_invalid_msg():
    messages = [123, {"role": "user", "content": 456}, {"content": "valid"}]
    result = list(_iter_text_from_messages(messages))
    assert result == [("user", "valid")]


def test_iter_text_from_messages_empty_content():
    messages = [{"role": "user", "content": ""}, {"content": []}]
    assert list(_iter_text_from_messages(messages)) == []


def test_iter_text_from_messages_mixed_parts():
    messages = [
        {"content": [{"text": "a"}, {"type": "text", "text": "b"}, {"text": ""}]}
    ]
    result = list(_iter_text_from_messages(messages))
    assert result == [("user", "a\nb")]


def test_iter_text_from_messages_no_dict_in_contents():
    messages = [{"contents": [123]}]  # invalid, to hit continue if not dict
    assert list(_iter_text_from_messages(messages)) == []


# Tests for _iter_text_from_response
def test_iter_text_from_response_openai_style():
    resp = {
        "choices": [
            {"message": {"content": "hello"}},
            {"message": {"content": [{"text": "world"}, {"text": "test"}]}},
        ]
    }
    result = list(_iter_text_from_response(resp))
    assert result == [("assistant", "hello\n\nworld\ntest")]


def test_iter_text_from_response_content_direct():
    resp = {"content": "direct content"}
    result = list(_iter_text_from_response(resp))
    assert result == [("assistant", "direct content")]


def test_iter_text_from_response_gemini_style():
    resp = {
        "candidates": [{"content": {"parts": [{"text": "part1"}, {"text": "part2"}]}}]
    }
    result = list(_iter_text_from_response(resp))
    assert result == [("assistant", "part1\npart2")]


def test_iter_text_from_response_invalid():
    assert list(_iter_text_from_response("not dict")) == []
    assert list(_iter_text_from_response({"choices": [123]})) == []
    assert (
        list(_iter_text_from_response({"candidates": [{"content": {"parts": [123]}}]}))
        == []
    )
    with mock.patch("builtins.isinstance", side_effect=Exception("mock error")):
        assert list(_iter_text_from_response({})) == []


def test_iter_text_from_response_empty():
    resp = {"choices": [{"message": {"content": ""}}], "content": ""}
    assert list(_iter_text_from_response(resp)) == []
    resp = {"candidates": [{"content": {"parts": [{"text": ""}]}}]}
    assert list(_iter_text_from_response(resp)) == []


def test_iter_text_from_response_not_parts_list():
    resp = {"candidates": [{"content": {"parts": "not list"}}]}
    assert list(_iter_text_from_response(resp)) == []


# Tests for _extract_text_fragments
def test_extract_text_fragments_openai():
    req = json.dumps({"messages": [{"content": "q"}], "prompt": "p"})
    resp = json.dumps({"choices": [{"message": {"content": "r"}}]})
    result = _extract_text_fragments(req, resp)
    assert result == [("user", "q"), ("user", "p"), ("assistant", "r")]


def test_extract_text_fragments_gemini():
    req = json.dumps({"contents": [{"parts": [{"text": "q1"}, {"text": "q2"}]}]})
    resp = json.dumps({"candidates": [{"content": {"parts": [{"text": "r"}]}}]})
    result = _extract_text_fragments(req, resp)
    assert result == [("user", "q1\nq2"), ("assistant", "r")]


def test_extract_text_fragments_invalid_json():
    result = _extract_text_fragments("invalid", "invalid")
    assert result == []
    with mock.patch("json.loads", side_effect=Exception("json error")):
        result = _extract_text_fragments('{"messages": []}', '{"choices": []}')
        assert result == []


def test_extract_text_fragments_deduplication():
    req = json.dumps({"messages": [{"content": "dup"}, {"content": "dup"}]})
    resp = json.dumps({"choices": [{"message": {"content": "dup"}}]})
    result = _extract_text_fragments(req, resp)
    assert len(result) == 2
    assert result == [("user", "dup"), ("assistant", "dup")]


def test_extract_text_fragments_mixed_formats():
    req = json.dumps(
        {
            "messages": [{"role": "user", "content": "msg"}],
            "prompt": "prompt",
            "contents": [{"parts": [{"text": "content"}]}],
        }
    )
    resp = json.dumps(
        {
            "choices": [{"message": {"content": "choice"}}],
            "content": "direct",
            "candidates": [{"content": {"parts": [{"text": "candidate"}]}}],
        }
    )
    result = _extract_text_fragments(req, resp)
    assert result == [
        ("user", "msg"),
        ("user", "prompt"),
        ("user", "content"),
        ("assistant", "choice"),
        ("assistant", "direct"),
        ("assistant", "candidate"),
    ]


def test_extract_text_fragments_empty_content_str_skipped(temp_db_path):
    conn = open_connection_with_pragmas(temp_db_path)
    conn.execute(
        "CREATE TABLE requests (request_id TEXT, endpoint TEXT, model_original TEXT, model_mapped TEXT, request_json TEXT, response_json TEXT);"
    )
    conn.execute(
        "INSERT INTO requests VALUES (?, ?, ?, ?, ?, ?);",
        ("r1", "", "", "", json.dumps({"messages": [{"content": "   "}]}), "{}"),
    )  # whitespace only
    conn.commit()
    conn.close()

    with mock.patch("ai_proxy.logdb.fts._sqlite_supports_fts5", return_value=True):
        from ai_proxy.logdb.fts import build_partition_fts

        indexed, skipped = build_partition_fts(temp_db_path)
        assert indexed == 0
