"""
Shared fixtures for ingest-related tests.

This module provides common test fixtures and utilities for testing
log ingestion, parsing, and processing functionality.
"""

import datetime as dt
import json
import os
import sqlite3
import tempfile
import pytest
from pathlib import Path
from typing import List, Dict, Any

from ai_proxy.logdb.ingest import ingest_logs
from ai_proxy.logdb.partitioning import ensure_partition_database
from ai_proxy.logdb.schema import open_connection_with_pragmas


@pytest.fixture
def sample_log_file(tmp_path):
    """
    Create a sample log file with realistic log entries.

    Returns:
        str: Path to the created log file
    """
    log_file = tmp_path / "sample.log"
    base_time = dt.datetime(2025, 9, 10, 12, 0, 0, tzinfo=dt.timezone.utc)

    log_entries = [
        {
            "timestamp": (base_time + dt.timedelta(seconds=i)).isoformat(),
            "level": "INFO",
            "endpoint": "/v1/chat/completions",
            "request": {
                "model": "gpt-3.5-turbo",
                "messages": [{"role": "user", "content": f"Test message {i}"}],
                "temperature": 0.7
            },
            "response": {
                "model": "gpt-3.5-turbo",
                "choices": [{"message": {"content": f"Response {i}"}}],
                "usage": {"total_tokens": 100 + i}
            },
            "status_code": 200,
            "latency_ms": 1500 + (i * 100),
            "api_key_hash": f"hash_{i}"
        }
        for i in range(5)
    ]

    with open(log_file, 'w', encoding='utf-8') as f:
        for entry in log_entries:
            json_line = json.dumps(entry, ensure_ascii=False)
            f.write(f"{entry['timestamp']} - {entry['level']} - {json_line}\n")

    return str(log_file)


@pytest.fixture
def sample_log_directory(tmp_path, sample_log_file):
    """
    Create a directory with multiple log files.

    Returns:
        str: Path to the logs directory
    """
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir(exist_ok=True)

    # Copy the sample log file
    import shutil
    shutil.copy2(sample_log_file, logs_dir / "app.log")

    # Create additional log files
    for i in range(2):
        rotated_log = logs_dir / f"app.log.{i + 1}"
        with open(rotated_log, 'w', encoding='utf-8') as f:
            f.write("# Rotated log file content\n")

    return str(logs_dir)


@pytest.fixture
def temp_db_directory(tmp_path):
    """
    Create a temporary directory for database partitions.

    Returns:
        str: Path to the database directory
    """
    db_dir = tmp_path / "db"
    db_dir.mkdir(exist_ok=True)
    return str(db_dir)


@pytest.fixture
def initialized_db(temp_db_directory):
    """
    Create and initialize a database with proper schema.

    Returns:
        tuple: (db_path, connection)
    """
    from ai_proxy.logdb.schema import ensure_schema

    db_path = os.path.join(temp_db_directory, "test.db")
    ensure_schema(db_path)

    conn = open_connection_with_pragmas(db_path)
    yield db_path, conn
    conn.close()


@pytest.fixture
def ingest_test_data():
    """
    Provide test data for ingest functionality testing.

    Returns:
        dict: Test data dictionary with various scenarios
    """
    return {
        'valid_entries': [
            {
                "timestamp": "2025-09-10T12:00:00.000Z",
                "endpoint": "/v1/chat/completions",
                "request": {"model": "gpt-3.5-turbo", "messages": []},
                "response": {"model": "gpt-3.5-turbo", "choices": []},
                "status_code": 200,
                "latency_ms": 1500
            }
        ],
        'invalid_entries': [
            {"timestamp": "invalid", "endpoint": "/test"},  # Invalid timestamp
            {"endpoint": "/test"},  # Missing required fields
            {"timestamp": "2025-09-10T12:00:00.000Z"}  # Missing endpoint
        ],
        'malformed_json': [
            '{"timestamp": "2025-09-10T12:00:00.000Z", "endpoint": "/test"',  # Incomplete JSON
            '{invalid json content}',  # Invalid JSON
        ]
    }


@pytest.fixture
def log_parser_test_data():
    """
    Provide test data specifically for log parsing functionality.

    Returns:
        dict: Test data for parser testing
    """
    return {
        'complete_log_line': '2025-09-10T12:00:00.000Z - INFO - {"endpoint": "/test", "request": {}, "response": {}}',
        'incomplete_log_line': '2025-09-10T12:00:00.000Z - INFO - {"endpoint": "/test"',
        'multiline_json': '''2025-09-10T12:00:00.000Z - INFO - {
  "endpoint": "/v1/chat/completions",
  "request": {
    "model": "gpt-3.5-turbo",
    "messages": [
      {
        "role": "user",
        "content": "Hello world"
      }
    ]
  },
  "response": {
    "choices": [
      {
        "message": {
          "content": "Hi there!"
        }
      }
    ]
  }
}''',
        'no_json_log_line': '2025-09-10T12:00:00.000Z - INFO - Plain text log entry',
        'empty_line': '',
        'whitespace_only': '   \n\t  '
    }


@pytest.fixture
def performance_test_logs(tmp_path):
    """
    Create a large log file for performance testing.

    Returns:
        str: Path to the large log file
    """
    log_file = tmp_path / "performance_test.log"
    base_time = dt.datetime(2025, 9, 10, 12, 0, 0, tzinfo=dt.timezone.utc)

    # Generate 1000 log entries for performance testing
    log_entries = []
    for i in range(1000):
        entry = {
            "timestamp": (base_time + dt.timedelta(seconds=i)).isoformat(),
            "level": "INFO",
            "endpoint": "/v1/chat/completions",
            "request": {
                "model": "gpt-3.5-turbo",
                "messages": [{"role": "user", "content": f"Performance test message {i}"}],
                "temperature": 0.7
            },
            "response": {
                "model": "gpt-3.5-turbo",
                "choices": [{"message": {"content": f"Response {i}"}}],
                "usage": {"total_tokens": 100 + i}
            },
            "status_code": 200,
            "latency_ms": 1500 + (i % 100),  # Vary latency
            "api_key_hash": f"hash_{i % 10}"  # Reuse some hashes
        }
        log_entries.append(entry)

    with open(log_file, 'w', encoding='utf-8') as f:
        for entry in log_entries:
            json_line = json.dumps(entry, ensure_ascii=False)
            f.write(f"{entry['timestamp']} - {entry['level']} - {json_line}\n")

    return str(log_file)


@pytest.fixture
def ingest_runner(tmp_path):
    """
    Factory fixture for running ingest with custom parameters.

    Returns:
        callable: Function to run ingest with custom parameters
    """
    def _run_ingest(logs_dir=None, db_dir=None, **kwargs):
        if logs_dir is None:
            logs_dir = str(tmp_path / "logs")
            os.makedirs(logs_dir, exist_ok=True)

        if db_dir is None:
            db_dir = str(tmp_path / "db")

        defaults = {
            'source_dir': logs_dir,
            'base_db_dir': db_dir,
            'since': None,
            'to': None
        }

        params = {**defaults, **kwargs}
        return ingest_logs(**params)

    return _run_ingest
