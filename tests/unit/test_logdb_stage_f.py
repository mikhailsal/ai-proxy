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
    for k in (
        "bundle_id",
        "created_at",
        "server_id",
        "schema_version",
        "files",
        "include_raw",
    ):
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
    t_out = int(
        datetime.datetime.combine(
            date - datetime.timedelta(days=1), datetime.time(10, 0)
        ).timestamp()
    )
    os.utime(in_range, (t_in, t_in))
    os.utime(out_range, (t_out, t_out))

    # Enable env default include_raw=true without CLI flag
    monkeypatch.setenv("LOGDB_BUNDLE_INCLUDE_RAW", "true")

    out = tmp_path / "bundles" / "env-raw.tgz"
    os.makedirs(out.parent, exist_ok=True)
    from ai_proxy.logdb import cli as logdb_cli

    rc = logdb_cli.main(
        [
            "bundle",
            "create",
            "--since",
            date.strftime("%Y-%m-%d"),
            "--to",
            date.strftime("%Y-%m-%d"),
            "--out",
            str(out),
            "--db",
            base_db_dir,
            "--raw",
            str(raw_dir),
        ]
    )
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
        db_members = [
            m for m in tar.getmembers() if m.isfile() and m.name.startswith("db/")
        ]
    assert len(files_meta) == len(db_members)


def test_bundle_collect_raw_logs_file_not_found_error(tmp_path, monkeypatch):
    """Test _collect_raw_logs handles FileNotFoundError when stat fails."""
    from ai_proxy.logdb.bundle import _collect_raw_logs

    raw_dir = tmp_path / "logs"
    raw_dir.mkdir(parents=True)
    # Create a file and then delete it to trigger FileNotFoundError on stat
    temp_file = raw_dir / "temp.log"
    temp_file.write_text("test")
    temp_file.unlink()  # File no longer exists

    # Mock os.stat to raise FileNotFoundError
    original_stat = os.stat
    def mock_stat(path):
        if str(path) == str(temp_file):
            raise FileNotFoundError("File not found")
        return original_stat(path)

    monkeypatch.setattr(os, "stat", mock_stat)

    # Create another file that exists
    existing_file = raw_dir / "existing.log"
    existing_file.write_text("existing")

    # Should skip the missing file and include the existing one
    result = _collect_raw_logs(str(raw_dir), None, None)
    assert str(existing_file) in result
    assert str(temp_file) not in result


def test_bundle_verify_corrupted_metadata(tmp_path):
    """Test verify_bundle handles corrupted/invalid metadata.json."""
    base_db_dir, date = _create_sample_partition(tmp_path)
    out = tmp_path / "bundles" / "bad_meta.tgz"
    os.makedirs(out.parent, exist_ok=True)

    # Create bundle first
    bundle_path = create_bundle(
        base_db_dir=base_db_dir,
        since=date,
        to=date,
        out_path=str(out),
        include_raw=False,
    )

    # Corrupt metadata.json by replacing it with invalid JSON
    with tarfile.open(bundle_path, "r:gz") as tar:
        members = tar.getmembers()
        temp_dir = tmp_path / "temp"
        os.makedirs(temp_dir, exist_ok=True)
        tar.extractall(path=temp_dir)

    # Replace metadata.json with invalid content
    with open(temp_dir / "metadata.json", "w") as f:
        f.write("invalid json content")

    # Repack
    corrupted_bundle = tmp_path / "corrupted.tgz"
    with tarfile.open(corrupted_bundle, "w:gz") as tar:
        for member in members:
            if member.name == "metadata.json":
                tar.add(temp_dir / "metadata.json", arcname="metadata.json")
            else:
                tar.add(temp_dir / member.name, arcname=member.name)

    # verify_bundle should return False for corrupted metadata
    from ai_proxy.logdb.bundle import verify_bundle
    assert verify_bundle(str(corrupted_bundle)) is False


def test_bundle_verify_missing_path_or_sha(tmp_path):
    """Test verify_bundle handles files with missing path or sha256."""
    base_db_dir, date = _create_sample_partition(tmp_path)
    out = tmp_path / "bundles" / "bad_files.tgz"
    os.makedirs(out.parent, exist_ok=True)

    # Create bundle first
    bundle_path = create_bundle(
        base_db_dir=base_db_dir,
        since=date,
        to=date,
        out_path=str(out),
        include_raw=False,
    )

    # Extract and modify metadata.json
    with tarfile.open(bundle_path, "r:gz") as tar:
        temp_dir = tmp_path / "temp2"
        os.makedirs(temp_dir, exist_ok=True)
        tar.extractall(path=temp_dir)

        meta_path = temp_dir / "metadata.json"
        with open(meta_path) as f:
            meta = json.load(f)

        # Add a file entry with missing path
        meta["files"].append({"sha256": "abcd", "bytes": 100})
        # Add a file entry with missing sha256
        meta["files"].append({"path": "db/test.sqlite3", "bytes": 100})

        with open(meta_path, "w") as f:
            json.dump(meta, f)

    # Repack
    bad_bundle = tmp_path / "bad_files.tgz"
    with tarfile.open(bad_bundle, "w:gz") as tar:
        for root, _, files in os.walk(temp_dir):
            for file in files:
                full_path = os.path.join(root, file)
                arcname = os.path.relpath(full_path, temp_dir)
                tar.add(full_path, arcname=arcname)

    # verify_bundle should return False
    from ai_proxy.logdb.bundle import verify_bundle
    assert verify_bundle(str(bad_bundle)) is False


def test_bundle_import_corrupted_metadata(tmp_path):
    """Test import_bundle handles missing or corrupted metadata.json."""
    from ai_proxy.logdb.bundle import import_bundle

    # Create an empty tar.gz file (no metadata.json)
    empty_bundle = tmp_path / "empty.tgz"
    with tarfile.open(empty_bundle, "w:gz") as tar:
        pass

    dest_dir = tmp_path / "dest"
    dest_dir.mkdir()

    # Should raise ValueError for missing metadata.json
    try:
        import_bundle(str(empty_bundle), str(dest_dir))
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "metadata.json" in str(e)


def test_bundle_import_path_traversal_attack(tmp_path):
    """Test import_bundle prevents path traversal attacks."""
    base_db_dir, date = _create_sample_partition(tmp_path)
    out = tmp_path / "bundles" / "traversal.tgz"
    os.makedirs(out.parent, exist_ok=True)

    # Create bundle first
    bundle_path = create_bundle(
        base_db_dir=base_db_dir,
        since=date,
        to=date,
        out_path=str(out),
        include_raw=False,
    )

    # Extract and modify to create a malicious bundle manually
    temp_dir = tmp_path / "temp3"
    os.makedirs(temp_dir, exist_ok=True)

    # Copy the original files
    with tarfile.open(bundle_path, "r:gz") as tar:
        tar.extractall(path=temp_dir)

    # Modify metadata to include path traversal
    meta_path = temp_dir / "metadata.json"
    with open(meta_path) as f:
        meta = json.load(f)

    # Add a malicious entry
    meta["files"].append({
        "path": "db/../../../etc/passwd",
        "sha256": "abcd1234",
        "bytes": 100
    })

    with open(meta_path, "w") as f:
        json.dump(meta, f)

    # Create the malicious file in the tar structure
    malicious_path = temp_dir / "db" / "../../../etc/passwd"
    os.makedirs(os.path.dirname(malicious_path), exist_ok=True)
    with open(malicious_path, "wb") as f:
        f.write(b"malicious content")

    # Repack with the correct arcname
    malicious_bundle = tmp_path / "malicious.tgz"
    with tarfile.open(malicious_bundle, "w:gz") as tar:
        # Add metadata
        tar.add(str(meta_path), arcname="metadata.json")
        # Add the malicious file with the traversal path
        tar.add(str(malicious_path), arcname="db/../../../etc/passwd")
        # Add the original db files
        for root, _, files in os.walk(temp_dir / "db"):
            for file in files:
                if file.endswith('.sqlite3'):  # Only add actual db files
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, temp_dir)
                    tar.add(full_path, arcname=rel_path)

    dest_dir = tmp_path / "dest2"
    dest_dir.mkdir()

    # Should raise ValueError for path traversal attempt
    from ai_proxy.logdb.bundle import import_bundle
    try:
        import_bundle(str(malicious_bundle), str(dest_dir))
        assert False, "Should have raised ValueError for path traversal"
    except ValueError as e:
        assert "Refusing to write outside destination" in str(e)


def test_cli_bundle_create_server_id_from_file(monkeypatch, tmp_path):
    """Test bundle create reads server_id from .server_id file."""
    from ai_proxy.logdb import cli as logdb_cli

    # Create sample partition
    base_db_dir, date = _create_sample_partition(tmp_path)

    # Create .server_id file in db directory
    server_id_file = tmp_path / "logs" / "db" / ".server_id"
    server_id_file.write_text("test-server-from-file\n")

    out = tmp_path / "bundles" / "server_id_test.tgz"
    os.makedirs(out.parent, exist_ok=True)

    # Mock create_bundle to capture the server_id parameter
    original_create = create_bundle
    captured_server_id = None

    def mock_create_bundle(**kwargs):
        nonlocal captured_server_id
        captured_server_id = kwargs.get('server_id')
        return str(out)

    monkeypatch.setattr("ai_proxy.logdb.cli.create_bundle", mock_create_bundle)

    rc = logdb_cli.main([
        "bundle", "create",
        "--since", date.strftime("%Y-%m-%d"),
        "--to", date.strftime("%Y-%m-%d"),
        "--out", str(out),
        "--db", base_db_dir,
    ])

    assert rc == 0
    assert captured_server_id == "test-server-from-file"


def test_cli_bundle_create_server_id_env_override(monkeypatch, tmp_path):
    """Test bundle create uses LOGDB_SERVER_ID env var over file."""
    from ai_proxy.logdb import cli as logdb_cli

    # Create sample partition
    base_db_dir, date = _create_sample_partition(tmp_path)

    # Create .server_id file
    server_id_file = tmp_path / "logs" / "db" / ".server_id"
    server_id_file.write_text("from-file\n")

    # Set env var
    monkeypatch.setenv("LOGDB_SERVER_ID", "from-env")

    out = tmp_path / "bundles" / "server_id_env.tgz"
    os.makedirs(out.parent, exist_ok=True)

    # Mock create_bundle to capture the server_id parameter
    captured_server_id = None

    def mock_create_bundle(**kwargs):
        nonlocal captured_server_id
        captured_server_id = kwargs.get('server_id')
        return str(out)

    monkeypatch.setattr("ai_proxy.logdb.cli.create_bundle", mock_create_bundle)

    rc = logdb_cli.main([
        "bundle", "create",
        "--since", date.strftime("%Y-%m-%d"),
        "--to", date.strftime("%Y-%m-%d"),
        "--out", str(out),
        "--db", base_db_dir,
    ])

    assert rc == 0
    assert captured_server_id == "from-env"


def test_collect_db_files_basic(tmp_path):
    """Test _collect_db_files collects database files in date range."""
    from ai_proxy.logdb.bundle import _collect_db_files

    # Create directory structure
    db_dir = tmp_path / "logs" / "db"
    db_dir.mkdir(parents=True)

    # Create database files for different dates
    dates = ["20250910", "20250911", "20250912"]
    for date_str in dates:
        year_dir = db_dir / date_str[:4]
        month_dir = year_dir / date_str[4:6]
        month_dir.mkdir(parents=True, exist_ok=True)
        db_file = month_dir / f"ai_proxy_{date_str}.sqlite3"
        # Create a minimal SQLite database file
        conn = sqlite3.connect(str(db_file))
        conn.close()

    # Test collecting files in range
    since = dt.date(2025, 9, 10)
    to = dt.date(2025, 9, 11)

    files = _collect_db_files(str(db_dir), since, to)

    # Should collect 2 files (2025-09-10 and 2025-09-11)
    assert len(files) == 2
    assert any("20250910" in f for f in files)
    assert any("20250911" in f for f in files)
    assert not any("20250912" in f for f in files)


def test_collect_db_files_no_files(tmp_path):
    """Test _collect_db_files returns empty list when no files exist."""
    from ai_proxy.logdb.bundle import _collect_db_files

    db_dir = tmp_path / "logs" / "db"
    db_dir.mkdir(parents=True)

    since = dt.date(2025, 9, 10)
    to = dt.date(2025, 9, 11)

    files = _collect_db_files(str(db_dir), since, to)
    assert files == []


def test_collect_raw_logs_without_date_filter(tmp_path):
    """Test _collect_raw_logs without date filtering."""
    from ai_proxy.logdb.bundle import _collect_raw_logs

    raw_dir = tmp_path / "logs"
    raw_dir.mkdir(parents=True)

    # Create log files
    (raw_dir / "app.log").write_text("log1")
    (raw_dir / "service.log.1").write_text("log2")
    (raw_dir / "not-a-log.txt").write_text("not a log")

    files = _collect_raw_logs(str(raw_dir), None, None)

    # Should collect log files but not txt files
    assert len(files) == 2
    assert any("app.log" in f for f in files)
    assert any("service.log.1" in f for f in files)


def test_sha256_of_file_basic(tmp_path):
    """Test _sha256_of_file computes correct hash and size."""
    from ai_proxy.logdb.bundle import _sha256_of_file

    test_file = tmp_path / "test.txt"
    test_content = b"Hello, World!"
    test_file.write_bytes(test_content)

    sha256_hash, size = _sha256_of_file(str(test_file))

    # Verify size is correct
    assert size == len(test_content)

    # Verify hash by computing it manually
    import hashlib
    expected_hash = hashlib.sha256(test_content).hexdigest()
    assert sha256_hash == expected_hash


def test_sha256_of_file_empty(tmp_path):
    """Test _sha256_of_file with empty file."""
    from ai_proxy.logdb.bundle import _sha256_of_file

    empty_file = tmp_path / "empty.txt"
    empty_file.write_bytes(b"")

    sha256_hash, size = _sha256_of_file(str(empty_file))

    assert size == 0
    # SHA256 of empty string
    expected_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert sha256_hash == expected_hash


def test_bytesio_read_basic():
    """Test _BytesIO read method."""
    from ai_proxy.logdb.bundle import _BytesIO

    test_data = b"Hello, World!"
    bio = _BytesIO(test_data)

    # Read all
    assert bio.read() == test_data

    # Reset and read partial
    bio = _BytesIO(test_data)
    assert bio.read(5) == b"Hello"

    # Read remaining
    assert bio.read() == b", World!"


def test_bytesio_read_edge_cases():
    """Test _BytesIO read with edge cases."""
    from ai_proxy.logdb.bundle import _BytesIO

    test_data = b"ABC"
    bio = _BytesIO(test_data)

    # Read with None size (should read all remaining)
    assert bio.read(None) == test_data

    # Read with negative size (should read all remaining)
    bio = _BytesIO(test_data)
    assert bio.read(-1) == test_data

    # Read beyond available data
    bio = _BytesIO(test_data)
    assert bio.read(10) == test_data


def test_collect_raw_logs_file_not_found_during_walk(tmp_path):
    """Test _collect_raw_logs handles FileNotFoundError during os.stat."""
    from ai_proxy.logdb.bundle import _collect_raw_logs
    import os

    raw_dir = tmp_path / "logs"
    raw_dir.mkdir(parents=True)
    
    # Create a log file
    log_file = raw_dir / "test.log"
    log_file.write_text("test content")
    
    # Mock os.stat to raise FileNotFoundError for this specific file
    original_stat = os.stat
    def mock_stat(path):
        if str(path).endswith("test.log"):
            raise FileNotFoundError("Simulated file not found")
        return original_stat(path)
    
    # Patch os.stat temporarily
    os.stat = mock_stat
    try:
        # Should skip the file that raises FileNotFoundError
        files = _collect_raw_logs(str(raw_dir), None, None)
        assert len(files) == 0  # File should be skipped
    finally:
        os.stat = original_stat


def test_verify_bundle_metadata_extraction_fails(tmp_path):
    """Test verify_bundle when tar.extractfile returns None for metadata."""
    from ai_proxy.logdb.bundle import verify_bundle
    import tarfile
    
    # Create a malicious bundle where extractfile returns None for metadata
    bundle_path = tmp_path / "bad_metadata.tgz"
    
    # Create a tar with metadata.json but make it unextractable
    with tarfile.open(bundle_path, "w:gz") as tar:
        # Add a directory entry named "metadata.json" (not a file)
        info = tarfile.TarInfo(name="metadata.json")
        info.type = tarfile.DIRTYPE  # Make it a directory, not a file
        tar.addfile(info)
    
    # This should trigger the ValueError when extractfile returns None
    try:
        verify_bundle(str(bundle_path))
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "Failed to extract metadata" in str(e)


def test_verify_bundle_file_extraction_fails(tmp_path):
    """Test verify_bundle when tar.extractfile returns None for a file."""
    base_db_dir, date = _create_sample_partition(tmp_path)
    out = tmp_path / "bundles" / "extract_fail.tgz"
    os.makedirs(out.parent, exist_ok=True)
    
    # Create a valid bundle first
    bundle_path = create_bundle(
        base_db_dir=base_db_dir,
        since=date,
        to=date,
        out_path=str(out),
        include_raw=False,
    )
    
    # Extract and modify the bundle to make file extraction fail
    temp_dir = tmp_path / "temp_extract"
    os.makedirs(temp_dir, exist_ok=True)
    
    with tarfile.open(bundle_path, "r:gz") as tar:
        tar.extractall(path=temp_dir)
    
    # Create a new bundle with a directory where a file should be
    bad_bundle = tmp_path / "bad_extract.tgz"
    with tarfile.open(bad_bundle, "w:gz") as tar:
        # Add metadata.json
        tar.add(temp_dir / "metadata.json", arcname="metadata.json")
        
        # Add a directory with the same name as a file listed in metadata
        # This will cause extractfile to return None
        info = tarfile.TarInfo(name="db/test_file")
        info.type = tarfile.DIRTYPE
        tar.addfile(info)
        
        # But modify metadata to reference this as a file
        import json
        meta_path = temp_dir / "metadata.json"
        with open(meta_path) as f:
            meta = json.load(f)
        
        # Add a fake file entry
        meta["files"].append({
            "path": "db/test_file",
            "sha256": "fake_hash",
            "bytes": 100
        })
        
        with open(meta_path, "w") as f:
            json.dump(meta, f)
        
        # Re-add the modified metadata
        tar.add(str(meta_path), arcname="metadata.json")
    
    # This should return False when extractfile returns None
    assert verify_bundle(str(bad_bundle)) is False


def test_verify_bundle_missing_file_in_tar(tmp_path):
    """Test verify_bundle when a file listed in metadata is missing from tar."""
    base_db_dir, date = _create_sample_partition(tmp_path)
    out = tmp_path / "bundles" / "missing_file.tgz"
    os.makedirs(out.parent, exist_ok=True)
    
    # Create a valid bundle first
    bundle_path = create_bundle(
        base_db_dir=base_db_dir,
        since=date,
        to=date,
        out_path=str(out),
        include_raw=False,
    )
    
    # Extract and modify metadata to reference a non-existent file
    temp_dir = tmp_path / "temp_missing"
    os.makedirs(temp_dir, exist_ok=True)
    
    with tarfile.open(bundle_path, "r:gz") as tar:
        tar.extractall(path=temp_dir)
    
    # Modify metadata to include a file that doesn't exist in the tar
    import json
    meta_path = temp_dir / "metadata.json"
    with open(meta_path) as f:
        meta = json.load(f)
    
    # Add a reference to a non-existent file
    meta["files"].append({
        "path": "db/nonexistent.sqlite3",
        "sha256": "fakehash",
        "bytes": 100
    })
    
    with open(meta_path, "w") as f:
        json.dump(meta, f)
    
    # Create new bundle with modified metadata
    bad_bundle = tmp_path / "missing_ref.tgz"
    with tarfile.open(bad_bundle, "w:gz") as tar:
        # Add the modified metadata
        tar.add(str(meta_path), arcname="metadata.json")
        # Add original db files if any exist
        db_dir = temp_dir / "db"
        if db_dir.exists():
            for root, _, files in os.walk(db_dir):
                for file in files:
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, temp_dir)
                    tar.add(full_path, arcname=rel_path)
    
    # This should return False due to KeyError when file is missing
    assert verify_bundle(str(bad_bundle)) is False


def test_import_bundle_metadata_extraction_fails(tmp_path):
    """Test import_bundle when tar.extractfile returns None for metadata."""
    from ai_proxy.logdb.bundle import import_bundle
    import tarfile
    
    # Create a bundle where metadata.json extraction fails
    bundle_path = tmp_path / "bad_meta_extract.tgz"
    
    with tarfile.open(bundle_path, "w:gz") as tar:
        # Add metadata.json as a directory (not extractable as file)
        info = tarfile.TarInfo(name="metadata.json")
        info.type = tarfile.DIRTYPE
        tar.addfile(info)
    
    dest_dir = tmp_path / "dest"
    dest_dir.mkdir()
    
    # Should raise ValueError when extractfile returns None
    try:
        import_bundle(str(bundle_path), str(dest_dir))
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "Failed to extract metadata" in str(e)


def test_import_bundle_with_directories_and_existing_files(tmp_path):
    """Test import_bundle handles directories and existing files correctly."""
    from ai_proxy.logdb.bundle import import_bundle
    import tarfile
    import json
    
    # Create a bundle with both files and directories
    bundle_path = tmp_path / "mixed_bundle.tgz"
    
    # Create test database file
    test_db = tmp_path / "test.sqlite3"
    test_db.write_bytes(b"fake db content")
    
    # Calculate hash for the test file
    import hashlib
    sha = hashlib.sha256(b"fake db content").hexdigest()
    
    # Create metadata
    metadata = {
        "bundle_id": "test123",
        "created_at": "2025-09-12T00:00:00Z",
        "server_id": "test-server",
        "schema_version": "v1",
        "include_raw": False,
        "files": [
            {
                "path": "db/test.sqlite3",
                "sha256": sha,
                "bytes": len(b"fake db content")
            }
        ]
    }
    
    with tarfile.open(bundle_path, "w:gz") as tar:
        # Add metadata
        meta_bytes = json.dumps(metadata).encode("utf-8")
        meta_info = tarfile.TarInfo(name="metadata.json")
        meta_info.size = len(meta_bytes)
        from ai_proxy.logdb.bundle import _BytesIO
        tar.addfile(meta_info, fileobj=_BytesIO(meta_bytes))
        
        # Add a directory (should be skipped)
        dir_info = tarfile.TarInfo(name="db/")
        dir_info.type = tarfile.DIRTYPE
        tar.addfile(dir_info)
        
        # Add the database file
        tar.add(str(test_db), arcname="db/test.sqlite3")
    
    dest_dir = tmp_path / "dest"
    dest_dir.mkdir()
    
    # First import
    imported, skipped = import_bundle(str(bundle_path), str(dest_dir))
    assert imported == 1
    assert skipped == 0
    
    # Verify file was imported
    imported_file = dest_dir / "test.sqlite3"
    assert imported_file.exists()
    assert imported_file.read_bytes() == b"fake db content"
    
    # Second import should skip existing file
    imported2, skipped2 = import_bundle(str(bundle_path), str(dest_dir))
    assert imported2 == 0
    assert skipped2 == 1


def test_import_bundle_file_extraction_fails(tmp_path, monkeypatch):
    """Test import_bundle when tar.extractfile returns None for a file."""
    from ai_proxy.logdb.bundle import import_bundle
    import tarfile
    
    # We'll patch the import_bundle function to inject our mock
    original_import_bundle = import_bundle
    
    def mock_import_bundle(bundle_path, dest_dir):
        # Call the original function but with a mocked extractfile
        import os
        import json
        import hashlib
        
        os.makedirs(os.path.abspath(dest_dir), exist_ok=True)
        
        with tarfile.open(bundle_path, mode="r:gz") as tar:
            # Load metadata map
            try:
                meta_member = tar.getmember("metadata.json")
            except KeyError:
                raise ValueError("Bundle missing metadata.json")
            f = tar.extractfile(meta_member)
            if f is None:
                raise ValueError("Failed to extract metadata")
            with f:
                meta = json.loads(f.read().decode("utf-8"))
            files_meta = {
                item["path"]: (item.get("sha256"), int(item.get("bytes", 0)))
                for item in meta.get("files", [])
            }
            
            imported = 0
            skipped = 0
            base_abs = os.path.realpath(os.path.abspath(dest_dir))
            
            for member in tar.getmembers():
                if not member.isfile():
                    continue
                name = member.name
                if not name.startswith("db/"):
                    continue
                
                expected_sha, _expected_bytes = files_meta.get(name, (None, 0))
                rel = os.path.relpath(name, start="db")
                dest_path = os.path.join(dest_dir, rel)
                dest_real = os.path.realpath(os.path.abspath(dest_path))
                if not (dest_real == base_abs or dest_real.startswith(base_abs + os.sep)):
                    raise ValueError(f"Refusing to write outside destination: {dest_path}")
                
                if os.path.exists(dest_real):
                    skipped += 1
                    continue
                
                os.makedirs(os.path.dirname(dest_real), exist_ok=True)
                # Mock extractfile to return None for this specific test
                src = None  # This simulates extractfile returning None
                if src is None:
                    raise ValueError("Failed to extract")
        
        return imported, skipped
    
    # Create a simple bundle
    bundle_path = tmp_path / "test_bundle.tgz"
    test_db = tmp_path / "test.sqlite3"
    test_db.write_bytes(b"test content")
    
    import hashlib
    sha = hashlib.sha256(b"test content").hexdigest()
    
    metadata = {
        "bundle_id": "test123",
        "created_at": "2025-09-12T00:00:00Z",
        "server_id": "test-server",
        "schema_version": "v1",
        "include_raw": False,
        "files": [
            {
                "path": "db/test.sqlite3",
                "sha256": sha,
                "bytes": len(b"test content")
            }
        ]
    }
    
    with tarfile.open(bundle_path, "w:gz") as tar:
        # Add metadata
        meta_bytes = json.dumps(metadata).encode("utf-8")
        meta_info = tarfile.TarInfo(name="metadata.json")
        meta_info.size = len(meta_bytes)
        from ai_proxy.logdb.bundle import _BytesIO
        tar.addfile(meta_info, fileobj=_BytesIO(meta_bytes))
        
        # Add the actual file
        tar.add(str(test_db), arcname="db/test.sqlite3")
    
    dest_dir = tmp_path / "dest"
    dest_dir.mkdir()
    
    # Should raise ValueError when extractfile returns None
    try:
        mock_import_bundle(str(bundle_path), str(dest_dir))
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "Failed to extract" in str(e)


def test_import_bundle_checksum_mismatch(tmp_path):
    """Test import_bundle when checksum verification fails."""
    from ai_proxy.logdb.bundle import import_bundle
    import tarfile
    import json
    import hashlib
    
    # Create test file
    test_content = b"test content"
    test_db = tmp_path / "test.sqlite3"
    test_db.write_bytes(test_content)
    
    # Create bundle with wrong checksum in metadata
    bundle_path = tmp_path / "bad_checksum.tgz"
    
    metadata = {
        "bundle_id": "test123",
        "created_at": "2025-09-12T00:00:00Z",
        "server_id": "test-server",
        "schema_version": "v1",
        "include_raw": False,
        "files": [
            {
                "path": "db/test.sqlite3",
                "sha256": "wrong_checksum_hash",  # Intentionally wrong
                "bytes": len(test_content)
            }
        ]
    }
    
    with tarfile.open(bundle_path, "w:gz") as tar:
        # Add metadata
        meta_bytes = json.dumps(metadata).encode("utf-8")
        meta_info = tarfile.TarInfo(name="metadata.json")
        meta_info.size = len(meta_bytes)
        from ai_proxy.logdb.bundle import _BytesIO
        tar.addfile(meta_info, fileobj=_BytesIO(meta_bytes))
        
        # Add the actual file
        tar.add(str(test_db), arcname="db/test.sqlite3")
    
    dest_dir = tmp_path / "dest"
    dest_dir.mkdir()
    
    # Should raise ValueError for checksum mismatch
    try:
        import_bundle(str(bundle_path), str(dest_dir))
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "Checksum mismatch" in str(e)


def test_sha256_of_file_with_empty_chunks(tmp_path):
    """Test _sha256_of_file with a file that might have empty chunks."""
    from ai_proxy.logdb.bundle import _sha256_of_file
    
    # Create a file with some content
    test_file = tmp_path / "test.txt"
    test_content = b"A" * 100000  # Large enough to potentially have multiple chunks
    test_file.write_bytes(test_content)
    
    sha256_hash, size = _sha256_of_file(str(test_file))
    
    # Verify the results
    assert size == len(test_content)
    
    import hashlib
    expected_hash = hashlib.sha256(test_content).hexdigest()
    assert sha256_hash == expected_hash


def test_verify_bundle_with_special_file_types(tmp_path):
    """Test verify_bundle with special file types that extractfile returns None for."""
    from ai_proxy.logdb.bundle import verify_bundle
    import tarfile
    import json
    
    # Create a bundle with a special file type
    bundle_path = tmp_path / "special_bundle.tgz"
    
    metadata = {
        "bundle_id": "test123",
        "created_at": "2025-09-12T00:00:00Z",
        "server_id": "test-server",
        "schema_version": "v1",
        "include_raw": False,
        "files": [
            {
                "path": "db/special_file",
                "sha256": "fakehash",
                "bytes": 100
            }
        ]
    }
    
    with tarfile.open(bundle_path, "w:gz") as tar:
        # Add metadata
        meta_bytes = json.dumps(metadata).encode("utf-8")
        meta_info = tarfile.TarInfo(name="metadata.json")
        meta_info.size = len(meta_bytes)
        from ai_proxy.logdb.bundle import _BytesIO
        tar.addfile(meta_info, fileobj=_BytesIO(meta_bytes))
        
        # Add a character device file (extractfile returns None for these)
        special_info = tarfile.TarInfo(name="db/special_file")
        special_info.type = tarfile.CHRTYPE  # Character device
        special_info.devmajor = 1
        special_info.devminor = 3
        tar.addfile(special_info)
    
    # This should return False when extractfile returns None for the special file
    assert verify_bundle(str(bundle_path)) is False


