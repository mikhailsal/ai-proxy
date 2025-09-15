import datetime as dt
import datetime
import os
import sqlite3
import tarfile
from pathlib import Path

from ai_proxy.logdb.bundle import create_bundle, verify_bundle
from ai_proxy.logdb.partitioning import compute_partition_path


def create_sample_partition(tmp_path):
    """Create a sample partition for bundle tests."""
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


def create_bundle_path(tmp_path, bundle_name="test_bundle.tgz"):
    """Create a bundle path in bundles directory."""
    bundle_path = tmp_path / "bundles" / bundle_name
    os.makedirs(bundle_path.parent, exist_ok=True)
    return bundle_path


def create_test_bundle(tmp_path, **kwargs):
    """Create a test bundle with default parameters."""
    base_db_dir, date = create_sample_partition(tmp_path)
    bundle_path = create_bundle_path(tmp_path)

    defaults = {
        'base_db_dir': base_db_dir,
        'since': date,
        'to': date,
        'out_path': str(bundle_path),
        'include_raw': False,
        'server_id': "test-server",
    }
    defaults.update(kwargs)

    return create_bundle(**defaults), base_db_dir, date


def create_raw_logs_structure(tmp_path, log_files=None):
    """Create a raw logs directory structure for testing."""
    raw_dir = tmp_path / "logs"
    os.makedirs(raw_dir, exist_ok=True)

    if log_files is None:
        log_files = [
            ("app.log", "hello\n"),
            ("service.log.1", "world\n"),
        ]

    created_files = []
    target_ts = int(datetime.datetime.combine(dt.date(2025, 9, 10), datetime.time(12, 0)).timestamp())

    for filename, content in log_files:
        file_path = raw_dir / filename
        file_path.write_text(content)
        os.utime(file_path, (target_ts, target_ts))
        created_files.append(file_path)

    return str(raw_dir), created_files


def create_test_database_file(tmp_path, filename="test.sqlite3", content=b"fake db content"):
    """Create a test database file."""
    db_file = tmp_path / filename
    db_file.write_bytes(content)
    return db_file


def create_bundle_metadata(bundle_path, modifications=None):
    """Extract, modify and repack bundle metadata."""
    temp_dir = bundle_path.parent / "temp"
    os.makedirs(temp_dir, exist_ok=True)

    # Extract bundle
    with tarfile.open(bundle_path, "r:gz") as tar:
        tar.extractall(path=temp_dir)

    # Read and modify metadata if needed
    import json
    meta_path = temp_dir / "metadata.json"
    with open(meta_path) as f:
        meta = json.load(f)

    if modifications:
        for key, value in modifications.items():
            if callable(value):
                meta[key] = value(meta.get(key))
            else:
                meta[key] = value

    with open(meta_path, "w") as f:
        json.dump(meta, f)

    # Repack
    new_bundle = bundle_path.parent / f"modified_{bundle_path.name}"
    with tarfile.open(new_bundle, "w:gz") as tar:
        for root, _, files in os.walk(temp_dir):
            for file in files:
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, temp_dir)
                tar.add(full_path, arcname=rel_path)

    return new_bundle


# Common constants
TEST_DATE = dt.date(2025, 9, 10)
TEST_SERVER_ID = "test-server"
BUNDLE_ID = "test123"
SCHEMA_VERSION = "v1"