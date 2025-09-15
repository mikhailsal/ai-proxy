"""
Shared fixtures for bundle-related tests.

This module provides common test fixtures and utilities for testing
bundle creation, verification, and import functionality.
"""

import datetime as dt
import os
import sqlite3
import pytest
from pathlib import Path

from ai_proxy.logdb.bundle import create_bundle, verify_bundle
from ai_proxy.logdb.partitioning import compute_partition_path


@pytest.fixture
def sample_partition(tmp_path):
    """
    Create a sample database partition for bundle testing.

    Returns:
        tuple: (base_db_dir, date) where date is the partition date
    """
    base = tmp_path / "logs" / "db"
    date = dt.date(2025, 9, 10)
    db_path = compute_partition_path(str(base), date)
    os.makedirs(os.path.dirname(db_path), exist_ok=True)

    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(
            """
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS servers (
              server_id TEXT PRIMARY KEY,
              hostname TEXT,
              env TEXT,
              first_seen_ts INTEGER
            );
            CREATE TABLE IF NOT EXISTS requests (
              request_id TEXT PRIMARY KEY,
              server_id TEXT NOT NULL,
              ts INTEGER NOT NULL,
              endpoint TEXT NOT NULL,
              model_original TEXT,
              model_mapped TEXT,
              status_code INTEGER,
              latency_ms REAL,
              api_key_hash TEXT,
              request_json TEXT NOT NULL,
              response_json TEXT NOT NULL,
              dialog_id TEXT
            );
            """
        )
        conn.commit()
    finally:
        conn.close()

    return str(base), date


@pytest.fixture
def sample_bundle(tmp_path, sample_partition):
    """
    Create a sample bundle file for testing.

    Returns:
        str: Path to the created bundle file
    """
    base_db_dir, date = sample_partition
    bundle_path = tmp_path / "test_bundle.tgz"
    os.makedirs(bundle_path.parent, exist_ok=True)

    return create_bundle(
        base_db_dir=base_db_dir,
        since=date,
        to=date,
        out_path=str(bundle_path),
        include_raw=False,
        server_id="test-server"
    )


@pytest.fixture
def corrupted_bundle(tmp_path, sample_bundle):
    """
    Create a corrupted bundle file for testing error handling.

    Returns:
        str: Path to the corrupted bundle file
    """
    import tarfile

    corrupted_path = tmp_path / "corrupted_bundle.tgz"

    # Copy original bundle
    with open(sample_bundle, 'rb') as src, open(corrupted_path, 'wb') as dst:
        data = src.read()
        # Corrupt the file by modifying some bytes
        if len(data) > 100:
            data = data[:50] + b'\x00\x00\x00\x00' + data[54:]
        dst.write(data)

    return str(corrupted_path)


@pytest.fixture
def bundle_with_metadata(tmp_path, sample_partition):
    """
    Create a bundle with custom metadata for testing.

    Returns:
        tuple: (bundle_path, expected_metadata)
    """
    base_db_dir, date = sample_partition
    bundle_path = tmp_path / "metadata_bundle.tgz"
    os.makedirs(bundle_path.parent, exist_ok=True)

    custom_server_id = "custom-test-server"
    schema_version = "v2.0"

    bundle_file = create_bundle(
        base_db_dir=base_db_dir,
        since=date,
        to=date,
        out_path=str(bundle_path),
        include_raw=False,
        server_id=custom_server_id,
        schema_version=schema_version
    )

    return bundle_file, {
        'server_id': custom_server_id,
        'schema_version': schema_version,
        'include_raw': False
    }


@pytest.fixture
def bundle_factory(tmp_path):
    """
    Factory fixture for creating bundles with custom parameters.

    Returns:
        callable: Function to create bundles with custom parameters
    """
    def _create_bundle(**kwargs):
        defaults = {
            'base_db_dir': None,
            'since': dt.date(2025, 9, 10),
            'to': dt.date(2025, 9, 10),
            'out_path': str(tmp_path / f"bundle_{dt.datetime.now().timestamp()}.tgz"),
            'include_raw': False,
            'server_id': "factory-server",
            'schema_version': "v1"
        }

        # Merge with provided kwargs
        params = {**defaults, **kwargs}

        # Create sample partition if not provided
        if params['base_db_dir'] is None:
            base = tmp_path / "logs" / "db"
            date = params['since']
            db_path = compute_partition_path(str(base), date)
            os.makedirs(os.path.dirname(db_path), exist_ok=True)

            conn = sqlite3.connect(db_path)
            try:
                conn.executescript(
                    """
                    PRAGMA journal_mode=WAL;
                    CREATE TABLE IF NOT EXISTS servers (
                      server_id TEXT PRIMARY KEY,
                      hostname TEXT,
                      env TEXT,
                      first_seen_ts INTEGER
                    );
                    CREATE TABLE IF NOT EXISTS requests (
                      request_id TEXT PRIMARY KEY,
                      server_id TEXT NOT NULL,
                      ts INTEGER NOT NULL,
                      endpoint TEXT NOT NULL,
                      model_original TEXT,
                      model_mapped TEXT,
                      status_code INTEGER,
                      latency_ms REAL,
                      api_key_hash TEXT,
                      request_json TEXT NOT NULL,
                      response_json TEXT NOT NULL,
                      dialog_id TEXT
                    );
                    """
                )
                conn.commit()
            finally:
                conn.close()

            params['base_db_dir'] = str(base)

        return create_bundle(**params)

    return _create_bundle
