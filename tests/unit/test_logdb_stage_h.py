import datetime as dt
import os
import sqlite3

from ai_proxy.logdb.bundle import create_bundle, verify_bundle
from ai_proxy.logdb.partitioning import compute_partition_path
from ai_proxy.logdb.transport import copy_with_resume


def _make_partition(base_dir: str, date: dt.date) -> str:
    db_path = compute_partition_path(base_dir, date)
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
    return db_path


def test_copy_with_resume_and_verify_bundle(tmp_path):
    base_db = tmp_path / "logs" / "db"
    date = dt.date(2025, 9, 10)
    _make_partition(str(base_db), date)

    bundle_path = tmp_path / "bundles" / "b-h.tgz"
    os.makedirs(bundle_path.parent, exist_ok=True)
    create_bundle(str(base_db), date, date, str(bundle_path), include_raw=False)

    # Simulate interrupted transfer by copying only a prefix to .part
    dest = tmp_path / "remote" / "b-h.tgz"
    os.makedirs(dest.parent, exist_ok=True)
    part = str(dest) + ".part"
    with open(bundle_path, "rb") as src, open(part, "wb") as dst:
        data = src.read(1024)
        dst.write(data)

    # Now resume copy
    size, sha = copy_with_resume(str(bundle_path), str(dest))
    assert os.path.isfile(dest)
    # Verify as bundle
    assert verify_bundle(str(dest)) is True


def test_copy_with_resume_idempotent_when_destination_exists(tmp_path):
    # Create a small file and copy twice
    src = tmp_path / "src.bin"
    src.write_bytes(b"hello world" * 100)
    dest = tmp_path / "dst.bin"
    size1, sha1 = copy_with_resume(str(src), str(dest))
    size2, sha2 = copy_with_resume(str(src), str(dest))
    assert size1 == size2 and sha1 == sha2


