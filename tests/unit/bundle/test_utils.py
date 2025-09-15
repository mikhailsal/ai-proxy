from ai_proxy.logdb.bundle import (
    _collect_raw_logs,
    _sha256_of_file,
    _BytesIO,
)


def test_collect_raw_logs_without_date_filter(tmp_path):
    """Test _collect_raw_logs without date filtering."""
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
    empty_file = tmp_path / "empty.txt"
    empty_file.write_bytes(b"")

    sha256_hash, size = _sha256_of_file(str(empty_file))

    assert size == 0
    # SHA256 of empty string
    expected_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert sha256_hash == expected_hash


def test_sha256_of_file_with_empty_chunks(tmp_path):
    """Test _sha256_of_file with a file that might have empty chunks."""
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


def test_bytesio_read_basic():
    """Test _BytesIO read method."""
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
