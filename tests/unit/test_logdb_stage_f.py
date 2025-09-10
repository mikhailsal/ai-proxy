import datetime as dt
import json
import os
import sqlite3
import tarfile

from ai_proxy.logdb.bundle import create_bundle, verify_bundle
from ai_proxy.logdb.partitioning import compute_partition_path


def _create_sample_partition(tmp_path):
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


def test_bundle_create_and_verify_ok(tmp_path):
    base_db_dir, date = _create_sample_partition(tmp_path)
    out = tmp_path / "bundles" / "b.tgz"
    os.makedirs(out.parent, exist_ok=True)

    bundle_path = create_bundle(
        base_db_dir=base_db_dir,
        since=date,
        to=date,
        out_path=str(out),
        include_raw=False,
    )
    assert os.path.isfile(bundle_path)
    assert verify_bundle(bundle_path) is True


def test_bundle_verify_detects_tamper(tmp_path):
    base_db_dir, date = _create_sample_partition(tmp_path)
    out = tmp_path / "b2.tgz"
    bundle_path = create_bundle(
        base_db_dir=base_db_dir,
        since=date,
        to=date,
        out_path=str(out),
        include_raw=False,
    )
    # Tamper: replace a file inside the tar
    # We'll extract, modify a db file bytes slightly, re-add without updating metadata
    tmp_dir = tmp_path / "tmp"
    os.makedirs(tmp_dir, exist_ok=True)
    with tarfile.open(bundle_path, "r:gz") as tar:
        tar.extractall(path=tmp_dir)
    # Find a db file under extracted db/
    db_dir = tmp_dir / "db"
    # If no db files present (e.g., if partition missing), create a dummy to keep test stable
    db_files = []
    for root, _dirs, names in os.walk(db_dir):
        for n in names:
            if n.endswith(".sqlite3"):
                db_files.append(os.path.join(root, n))
    if not db_files:
        # Should not happen because we created a partition file
        raise AssertionError("No db files in bundle")
    # Tamper: append one byte to the first db file
    with open(db_files[0], "ab") as f:
        f.write(b"\x00")
    # Repack tar without touching metadata.json
    tampered = tmp_path / "tampered.tgz"
    with tarfile.open(tampered, "w:gz") as tar:
        # add db tree
        tar.add(tmp_dir / "db", arcname="db")
        # add metadata.json as-is
        tar.add(tmp_dir / "metadata.json", arcname="metadata.json")

    assert verify_bundle(str(tampered)) is False


