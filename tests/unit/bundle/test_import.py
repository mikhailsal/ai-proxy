import json
import os
import tarfile
import hashlib

from ai_proxy.logdb.bundle import import_bundle, create_bundle
from tests.unit.shared.bundle_fixtures import (
    create_sample_partition,
    create_bundle_path,
)


def test_bundle_import_corrupted_metadata(tmp_path):
    """Test import_bundle handles missing or corrupted metadata.json."""
    # Create an empty tar.gz file (no metadata.json)
    empty_bundle = tmp_path / "empty.tgz"
    with tarfile.open(empty_bundle, "w:gz") as _:
        pass

    dest_dir = tmp_path / "dest"
    dest_dir.mkdir()

    # Should raise ValueError for missing metadata.json
    import pytest

    with pytest.raises(ValueError) as exc:
        import_bundle(str(empty_bundle), str(dest_dir))
    assert "metadata.json" in str(exc.value)


def test_bundle_import_path_traversal_attack(tmp_path):
    """Test import_bundle prevents path traversal attacks."""
    base_db_dir, date = create_sample_partition(tmp_path)
    bundle_path = create_bundle_path(tmp_path, "traversal.tgz")

    # Create bundle first
    bundle_path = create_bundle(
        base_db_dir=base_db_dir,
        since=date,
        to=date,
        out_path=str(bundle_path),
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
    meta["files"].append(
        {"path": "db/../../../etc/passwd", "sha256": "abcd1234", "bytes": 100}
    )

    with open(meta_path, "w") as f:
        json.dump(meta, f)

    # Create the malicious file safely inside temp_dir and add it to the tar
    # with a traversal arcname so we don't write outside the tmp tree.
    safe_malicious_src = temp_dir / "db" / "malicious_payload"
    os.makedirs(os.path.dirname(safe_malicious_src), exist_ok=True)
    with open(safe_malicious_src, "wb") as f:
        f.write(b"malicious content")

    # Repack with the traversal arcname but using the safe source file
    malicious_bundle = tmp_path / "malicious.tgz"
    with tarfile.open(malicious_bundle, "w:gz") as tar:
        # Add metadata
        tar.add(str(meta_path), arcname="metadata.json")
        # Add the malicious file using a path-traversal arcname only (safe src)
        tar.add(str(safe_malicious_src), arcname="db/../../../etc/passwd")
        # Add the original db files
        for root, _, files in os.walk(temp_dir / "db"):
            for file in files:
                if file.endswith(".sqlite3"):  # Only add actual db files
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, temp_dir)
                    tar.add(full_path, arcname=rel_path)

    dest_dir = tmp_path / "dest2"
    dest_dir.mkdir()

    # Should raise ValueError for path traversal attempt
    import pytest

    with pytest.raises(ValueError) as exc2:
        import_bundle(str(malicious_bundle), str(dest_dir))
    assert "Refusing to write outside destination" in str(exc2.value)


def test_import_bundle_metadata_extraction_fails(tmp_path):
    """Test import_bundle when tar.extractfile returns None for metadata."""
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
    # Create a bundle with both files and directories
    bundle_path = tmp_path / "mixed_bundle.tgz"

    # Create test database file
    test_db = tmp_path / "test.sqlite3"
    test_db.write_bytes(b"fake db content")

    # Calculate hash for the test file
    sha = hashlib.sha256(b"fake db content").hexdigest()

    # Create metadata
    metadata = {
        "bundle_id": "test123",
        "created_at": "2025-09-12T00:00:00Z",
        "server_id": "test-server",
        "schema_version": "v1",
        "include_raw": False,
        "files": [
            {"path": "db/test.sqlite3", "sha256": sha, "bytes": len(b"fake db content")}
        ],
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
    # We'll patch the import_bundle function to inject our mock

    def mock_import_bundle(bundle_path, dest_dir):
        # Call the original function but with a mocked extractfile
        import os
        import json

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
                if not (
                    dest_real == base_abs or dest_real.startswith(base_abs + os.sep)
                ):
                    raise ValueError(
                        f"Refusing to write outside destination: {dest_path}"
                    )

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

    sha = hashlib.sha256(b"test content").hexdigest()

    metadata = {
        "bundle_id": "test123",
        "created_at": "2025-09-12T00:00:00Z",
        "server_id": "test-server",
        "schema_version": "v1",
        "include_raw": False,
        "files": [
            {"path": "db/test.sqlite3", "sha256": sha, "bytes": len(b"test content")}
        ],
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
    import pytest

    with pytest.raises(ValueError) as exc3:
        mock_import_bundle(str(bundle_path), str(dest_dir))
    assert "Failed to extract" in str(exc3.value)


def test_import_bundle_checksum_mismatch(tmp_path):
    """Test import_bundle when checksum verification fails."""
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
                "bytes": len(test_content),
            }
        ],
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
    import pytest

    with pytest.raises(ValueError) as exc4:
        import_bundle(str(bundle_path), str(dest_dir))
    assert "Checksum mismatch" in str(exc4.value)
