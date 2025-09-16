import json
import os
import sqlite3
import tarfile

from ai_proxy.logdb.bundle import (
    verify_bundle,
    _collect_raw_logs,
    _collect_db_files,
)
from tests.unit.shared.bundle_fixtures import (
    create_sample_partition,
    create_bundle_path,
    create_test_bundle,
    create_bundle_metadata,
)


def test_bundle_verify_detects_tamper(tmp_path):
    """Test that bundle verification detects tampering."""
    bundle_path, base_db_dir, date = create_test_bundle(tmp_path)
    bundle_path = str(bundle_path)

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


def test_bundle_collect_raw_logs_file_not_found_error(tmp_path, monkeypatch):
    """Test _collect_raw_logs handles FileNotFoundError when stat fails."""
    raw_dir = tmp_path / "logs"
    raw_dir.mkdir(parents=True)
    # Create a file and then delete it to trigger FileNotFoundError on stat
    temp_file = raw_dir / "temp.log"
    temp_file.write_text("test")
    temp_file.unlink()  # File no longer exists

    # Mock os.stat to raise FileNotFoundError using monkeypatch for safe restore
    original_stat = os.stat
    def mock_stat(*args, **kwargs):
        # first positional arg is the path
        path = args[0] if args else kwargs.get('path')
        if path is not None and str(path) == str(temp_file):
            raise FileNotFoundError("File not found")
        return original_stat(*args, **kwargs)

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
    bundle_path, base_db_dir, date = create_test_bundle(tmp_path)

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
    assert verify_bundle(str(corrupted_bundle)) is False


def test_bundle_verify_missing_path_or_sha(tmp_path):
    """Test verify_bundle handles files with missing path or sha256."""
    bundle_path, base_db_dir, date = create_test_bundle(tmp_path)

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
    assert verify_bundle(str(bad_bundle)) is False


def test_collect_db_files_no_files(tmp_path):
    """Test _collect_db_files returns empty list when no files exist."""
    import datetime as dt

    db_dir = tmp_path / "logs" / "db"
    db_dir.mkdir(parents=True)

    since = dt.date(2025, 9, 10)
    to = dt.date(2025, 9, 11)

    files = _collect_db_files(str(db_dir), since, to)
    assert files == []


def test_verify_bundle_metadata_extraction_fails(tmp_path):
    """Test verify_bundle when tar.extractfile returns None for metadata."""
    # Create a malicious bundle where extractfile returns None for metadata
    bundle_path = tmp_path / "bad_metadata.tgz"

    # Create a tar with metadata.json but make it unextractable
    with tarfile.open(bundle_path, "w:gz") as tar:
        # Add a directory entry named "metadata.json" (not a file)
        info = tarfile.TarInfo(name="metadata.json")
        info.type = tarfile.DIRTYPE  # Make it a directory, not a file
        tar.addfile(info)

    # This should trigger the ValueError when extractfile returns None
    import pytest
    with pytest.raises(ValueError) as exc:
        verify_bundle(str(bundle_path))
    assert "Failed to extract metadata" in str(exc.value)


def test_verify_bundle_file_extraction_fails(tmp_path):
    """Test verify_bundle when tar.extractfile returns None for a file."""
    bundle_path, base_db_dir, date = create_test_bundle(tmp_path)

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
    bundle_path, base_db_dir, date = create_test_bundle(tmp_path)

    # Extract and modify metadata to reference a non-existent file
    temp_dir = tmp_path / "temp_missing"
    os.makedirs(temp_dir, exist_ok=True)

    with tarfile.open(bundle_path, "r:gz") as tar:
        tar.extractall(path=temp_dir)

    # Modify metadata to include a file that doesn't exist in the tar
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


def test_verify_bundle_with_special_file_types(tmp_path):
    """Test verify_bundle with special file types that extractfile returns None for."""
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
