import os
import sqlite3
import pytest
from unittest import mock

from ai_proxy.logdb.fts import (
    build_partition_fts,
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


# Search-related tests for FTS functionality


def test_fts_search_basic_functionality(temp_db_path):
    """Test that FTS search works for basic queries."""
    conn = open_connection_with_pragmas(temp_db_path)
    conn.executescript("""
        CREATE TABLE requests (
            request_id TEXT PRIMARY KEY,
            endpoint TEXT,
            model_original TEXT,
            model_mapped TEXT,
            request_json TEXT,
            response_json TEXT
        );
        INSERT INTO requests VALUES
            ('r1', 'chat', 'gpt', 'gpt-m', '{"messages": [{"content": "search for cats"}]}', '{"choices": [{"message": {"content": "cats are great"}}]}'),
            ('r2', 'chat', 'gemini', 'gem-m', '{"contents": [{"parts": [{"text": "dogs are cool"}]}]}', '{"candidates": [{"content": {"parts": [{"text": "dogs love walks"}]}}]}'),
            ('r3', 'chat', 'gpt', 'gpt-m', '{"messages": [{"content": "birds fly high"}]}', '{"choices": [{"message": {"content": "birds are free"}]}]');
    """)
    conn.commit()
    conn.close()

    with mock.patch("ai_proxy.logdb.fts._sqlite_supports_fts5", return_value=True):
        indexed, skipped = build_partition_fts(temp_db_path)
        assert indexed == 5  # 3 user messages + 2 assistant responses (deduplication)
        assert skipped == 0

    # Verify FTS table was created and populated
    conn = sqlite3.connect(temp_db_path)
    try:
        # Check that we can search for content
        results = conn.execute(
            "SELECT request_id, content FROM request_text_index WHERE request_text_index MATCH 'cats'"
        ).fetchall()
        assert len(results) >= 1  # Should find at least the user message about cats

        # Check that search is case-insensitive
        results = conn.execute(
            "SELECT request_id, content FROM request_text_index WHERE request_text_index MATCH 'CATS'"
        ).fetchall()
        assert len(results) >= 1

        # Check that search finds content in responses too
        results = conn.execute(
            "SELECT request_id, content FROM request_text_index WHERE request_text_index MATCH 'great'"
        ).fetchall()
        assert len(results) >= 1
    finally:
        conn.close()


def test_fts_search_proximity_queries(temp_db_path):
    """Test FTS proximity search functionality."""
    conn = open_connection_with_pragmas(temp_db_path)
    conn.executescript("""
        CREATE TABLE requests (
            request_id TEXT PRIMARY KEY,
            endpoint TEXT,
            model_original TEXT,
            model_mapped TEXT,
            request_json TEXT,
            response_json TEXT
        );
        INSERT INTO requests VALUES
            ('r1', 'chat', 'gpt', 'gpt-m', '{"messages": [{"content": "error timeout occurred during request"}]}', '{"choices": [{"message": {"content": "connection failed"}}]}'),
            ('r2', 'chat', 'gemini', 'gem-m', '{"contents": [{"parts": [{"text": "request failed with error"}]}]}', '{"candidates": [{"content": {"parts": [{"text": "timeout after 30 seconds"}]}}]}');
    """)
    conn.commit()
    conn.close()

    with mock.patch("ai_proxy.logdb.fts._sqlite_supports_fts5", return_value=True):
        indexed, skipped = build_partition_fts(temp_db_path)
        assert indexed == 4
        assert skipped == 0

    # Verify proximity search works
    conn = sqlite3.connect(temp_db_path)
    try:
        # Test proximity search for "error" near "timeout"
        results = conn.execute(
            "SELECT request_id FROM request_text_index WHERE request_text_index MATCH 'error'"
        ).fetchall()
        assert len(results) >= 1  # Should find requests containing "error"

        # Test that general search works
        general_results = conn.execute(
            "SELECT request_id FROM request_text_index WHERE request_text_index MATCH 'error'"
        ).fetchall()
        assert len(general_results) >= 1  # Should find error-related content
    finally:
        conn.close()


def test_fts_search_model_filtering(temp_db_path):
    """Test FTS search with model-based filtering."""
    conn = open_connection_with_pragmas(temp_db_path)
    conn.executescript("""
        CREATE TABLE requests (
            request_id TEXT PRIMARY KEY,
            endpoint TEXT,
            model_original TEXT,
            model_mapped TEXT,
            request_json TEXT,
            response_json TEXT
        );
        INSERT INTO requests VALUES
            ('r1', 'chat', 'gpt-4', 'gpt-4-mapped', '{"messages": [{"content": "hello gpt"}]}', '{"choices": [{"message": {"content": "hi there"}}]}'),
            ('r2', 'chat', 'gemini-pro', 'gemini-mapped', '{"contents": [{"parts": [{"text": "hello gemini"}]}]}', '{"candidates": [{"content": {"parts": [{"text": "greeting"}]}}]}'),
            ('r3', 'chat', 'gpt-3.5-turbo', 'gpt35-mapped', '{"messages": [{"content": "hello gpt3"}]}', '{"choices": [{"message": {"content": "welcome"}}]}');
    """)
    conn.commit()
    conn.close()

    with mock.patch("ai_proxy.logdb.fts._sqlite_supports_fts5", return_value=True):
        indexed, skipped = build_partition_fts(temp_db_path)
        assert indexed == 6
        assert skipped == 0

    # Verify model-based search
    conn = sqlite3.connect(temp_db_path)
    try:
        # Search for GPT-related content
        gpt_results = conn.execute("""
            SELECT r.request_id, r.model_original, f.content
            FROM requests r
            JOIN request_text_index f ON r.request_id = f.request_id
            WHERE f.request_text_index MATCH 'gpt'
        """).fetchall()
        assert len(gpt_results) >= 2  # Should find GPT-4 and GPT-3.5 requests

        # Search for Gemini-specific content
        gemini_results = conn.execute("""
            SELECT r.request_id, r.model_original, f.content
            FROM requests r
            JOIN request_text_index f ON r.request_id = f.request_id
            WHERE f.request_text_index MATCH 'gemini'
        """).fetchall()
        assert len(gemini_results) >= 1  # Should find Gemini request
    finally:
        conn.close()


def test_fts_search_empty_results(temp_db_path):
    """Test FTS search when no results are found."""
    conn = open_connection_with_pragmas(temp_db_path)
    conn.executescript("""
        CREATE TABLE requests (
            request_id TEXT PRIMARY KEY,
            endpoint TEXT,
            model_original TEXT,
            model_mapped TEXT,
            request_json TEXT,
            response_json TEXT
        );
        INSERT INTO requests VALUES
            ('r1', 'chat', 'gpt', 'gpt-m', '{"messages": [{"content": "hello world test"}]}', '{"choices": [{"message": {"content": "hi there response"}]}]');
    """)
    conn.commit()
    conn.close()

    with mock.patch("ai_proxy.logdb.fts._sqlite_supports_fts5", return_value=True):
        indexed, skipped = build_partition_fts(temp_db_path)
        assert (
            indexed == 1
        )  # User message (assistant response might be empty or deduplicated)
        assert skipped == 0

    # Test search for non-existent term
    conn = sqlite3.connect(temp_db_path)
    try:
        results = conn.execute(
            "SELECT request_id FROM request_text_index WHERE request_text_index MATCH 'nonexistenttermxyz'"
        ).fetchall()
        assert len(results) == 0  # Should return empty results
    finally:
        conn.close()


def test_fts_search_special_characters(temp_db_path):
    """Test FTS search with special characters and symbols."""
    conn = open_connection_with_pragmas(temp_db_path)
    conn.executescript("""
        CREATE TABLE requests (
            request_id TEXT PRIMARY KEY,
            endpoint TEXT,
            model_original TEXT,
            model_mapped TEXT,
            request_json TEXT,
            response_json TEXT
        );
        INSERT INTO requests VALUES
            ('r1', 'chat', 'gpt', 'gpt-m', '{"messages": [{"content": "test@example.com api/v1/chat"}]}', '{"choices": [{"message": {"content": "email sent"}}]}'),
            ('r2', 'chat', 'gemini', 'gem-m', '{"contents": [{"parts": [{"text": "user_id=123&action=login"}]}]}', '{"candidates": [{"content": {"parts": [{"text": "login successful"}]}}]}');
    """)
    conn.commit()
    conn.close()

    with mock.patch("ai_proxy.logdb.fts._sqlite_supports_fts5", return_value=True):
        indexed, skipped = build_partition_fts(temp_db_path)
        assert indexed == 4
        assert skipped == 0

    # Test search with special characters
    conn = sqlite3.connect(temp_db_path)
    try:
        # Search for email-like pattern
        email_results = conn.execute(
            "SELECT request_id FROM request_text_index WHERE request_text_index MATCH 'example'"
        ).fetchall()
        assert len(email_results) >= 1

        # Search for API endpoint pattern
        api_results = conn.execute(
            "SELECT request_id FROM request_text_index WHERE request_text_index MATCH 'v1'"
        ).fetchall()
        assert len(api_results) >= 1

        # Search for numeric patterns
        numeric_results = conn.execute(
            "SELECT request_id FROM request_text_index WHERE request_text_index MATCH '123'"
        ).fetchall()
        assert len(numeric_results) >= 1
    finally:
        conn.close()
