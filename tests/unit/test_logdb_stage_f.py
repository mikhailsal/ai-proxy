import datetime as dt
import datetime
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
        server_id="srv-test",
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


def test_bundle_create_with_include_raw_and_metadata(tmp_path):
    base_db_dir, date = _create_sample_partition(tmp_path)

    # Create a small raw logs tree
    raw_dir = tmp_path / "logs"
    os.makedirs(raw_dir, exist_ok=True)
    # two log files in nested dirs
    f1 = raw_dir / "app.log"
    f2 = raw_dir / "sub" / "service.log.1"
    os.makedirs(f2.parent, exist_ok=True)
    f1.write_text("hello\n")
    f2.write_text("world\n")
    # Set mtime within the date range to ensure inclusion
    target_ts = int(datetime.datetime.combine(date, datetime.time(12, 0)).timestamp())
    os.utime(f1, (target_ts, target_ts))
    os.utime(f2, (target_ts, target_ts))

    out = tmp_path / "bundles" / "with_raw.tgz"
    os.makedirs(out.parent, exist_ok=True)

    bundle_path = create_bundle(
        base_db_dir=base_db_dir,
        since=date,
        to=date,
        out_path=str(out),
        include_raw=True,
        raw_logs_dir=str(raw_dir),
        server_id="srv-raw",
    )
    assert os.path.isfile(bundle_path)

    # Verify should still pass
    assert verify_bundle(bundle_path) is True

    # Inspect metadata.json
    with tarfile.open(bundle_path, "r:gz") as tar:
        meta_member = tar.getmember("metadata.json")
        with tar.extractfile(meta_member) as f:
            data = json.loads(f.read().decode("utf-8"))
    # Required fields present
    for k in ("bundle_id", "created_at", "server_id", "schema_version", "files", "include_raw"):
        assert k in data
    assert data["include_raw"] is True
    assert isinstance(data["server_id"], str) and data["server_id"]
    # Ensure at least one raw file is referenced
    raw_refs = [x for x in data["files"] if x["path"].startswith("raw/")]
    assert len(raw_refs) >= 2


def test_raw_logs_date_filtering_and_env_default(tmp_path, monkeypatch):
    base_db_dir, date = _create_sample_partition(tmp_path)

    raw_dir = tmp_path / "logs"
    os.makedirs(raw_dir, exist_ok=True)
    in_range = raw_dir / "in.log"
    out_range = raw_dir / "out.log"
    in_range.write_text("in\n")
    out_range.write_text("out\n")

    # Set mtimes: in-range on 'date', out-of-range one day before
    t_in = int(datetime.datetime.combine(date, datetime.time(10, 0)).timestamp())
    t_out = int(datetime.datetime.combine(date - datetime.timedelta(days=1), datetime.time(10, 0)).timestamp())
    os.utime(in_range, (t_in, t_in))
    os.utime(out_range, (t_out, t_out))

    # Enable env default include_raw=true without CLI flag
    monkeypatch.setenv("LOGDB_BUNDLE_INCLUDE_RAW", "true")

    out = tmp_path / "bundles" / "env-raw.tgz"
    os.makedirs(out.parent, exist_ok=True)
    from ai_proxy.logdb import cli as logdb_cli
    rc = logdb_cli.main([
        "bundle", "create",
        "--since", date.strftime("%Y-%m-%d"),
        "--to", date.strftime("%Y-%m-%d"),
        "--out", str(out),
        "--db", base_db_dir,
        "--raw", str(raw_dir),
    ])
    assert rc == 0
    # Verify only in-range raw included
    import tarfile
    with tarfile.open(out, "r:gz") as tar:
        names = [m.name for m in tar.getmembers() if m.isfile()]
        raw_names = [n for n in names if n.startswith("raw/")]
        # Only one raw file should be included
        assert len(raw_names) == 1 and raw_names[0].endswith("in.log")


def test_bundle_metadata_files_count_matches_tar(tmp_path):
    base_db_dir, date = _create_sample_partition(tmp_path)
    out = tmp_path / "bundles" / "meta_count.tgz"
    os.makedirs(out.parent, exist_ok=True)

    bundle_path = create_bundle(
        base_db_dir=base_db_dir,
        since=date,
        to=date,
        out_path=str(out),
        include_raw=False,
    )

    # Count entries in tar under db/ and compare to metadata files entries
    with tarfile.open(bundle_path, "r:gz") as tar:
        meta = json.loads(tar.extractfile("metadata.json").read().decode("utf-8"))  # type: ignore[arg-type]
        files_meta = [x for x in meta.get("files", []) if isinstance(x, dict)]
        db_members = [m for m in tar.getmembers() if m.isfile() and m.name.startswith("db/")]
    assert len(files_meta) == len(db_members)


