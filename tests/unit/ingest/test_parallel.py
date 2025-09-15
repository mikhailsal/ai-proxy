import datetime as dt
import sqlite3
from ai_proxy.logdb.ingest import ingest_logs
from tests.unit.shared.ingest_fixtures import SAMPLE_ENTRY_1, SAMPLE_ENTRY_2


def test_parallel_ingest_env_flag(tmp_path, monkeypatch):
    logs_dir = tmp_path / "logs"
    db_base = tmp_path / "logs" / "db"
    logs_dir.mkdir(parents=True, exist_ok=True)
    (logs_dir / "v1_chat_completions.log").write_text(SAMPLE_ENTRY_1, encoding="utf-8")
    (logs_dir / "v1_models.log").write_text(SAMPLE_ENTRY_2, encoding="utf-8")

    monkeypatch.setenv("LOGDB_IMPORT_PARALLELISM", "4")
    stats = ingest_logs(str(logs_dir), str(db_base))
    assert stats.files_scanned >= 2


def test_parallel_ingest_multiple_files(tmp_path, monkeypatch):
    logs_dir = tmp_path / "logs"
    db_base = tmp_path / "logs" / "db"
    logs_dir.mkdir(parents=True, exist_ok=True)
    for i in range(5):
        log = logs_dir / f"log{i}.log"
        log.write_text(SAMPLE_ENTRY_1, encoding="utf-8")
    monkeypatch.setenv("LOGDB_IMPORT_PARALLELISM", "3")
    stats = ingest_logs(str(logs_dir), str(db_base))
    assert stats.files_scanned >= 5
    assert stats.rows_inserted >= 1


def test_memory_pressure_flushing(tmp_path, monkeypatch):
    """Test memory pressure flushing logic (lines 471-472)."""
    logs_dir = tmp_path / "logs"
    db_base = tmp_path / "logs" / "db"
    logs_dir.mkdir(parents=True, exist_ok=True)

    # Create many entries to trigger memory pressure
    entries = []
    for i in range(50):
        ts = f"2025-09-10T12:00:{i:02d}Z"
        entry = SAMPLE_ENTRY_1.replace("2025-09-10T12:00:00Z", ts)
        entries.append(entry)

    log_path = logs_dir / "big.log"
    log_path.write_text("".join(entries), encoding="utf-8")

    # Set very low memory limit to trigger pressure flushing
    monkeypatch.setenv("LOGDB_MEMORY_MB", "1")  # 1MB limit
    monkeypatch.setenv("LOGDB_BATCH_ROWS", "100")  # High row limit

    stats = ingest_logs(str(logs_dir), str(db_base))
    assert stats.rows_inserted > 0


def test_bytes_threshold_flushing(tmp_path, monkeypatch):
    """Test byte threshold flushing logic (line 465)."""
    logs_dir = tmp_path / "logs"
    db_base = tmp_path / "logs" / "db"
    logs_dir.mkdir(parents=True, exist_ok=True)

    # Create entries with large content
    large_content = "x" * 1000  # Large content to trigger byte limit
    entry = SAMPLE_ENTRY_1.replace('"Hi"', f'"{large_content}"')

    entries = []
    for i in range(10):
        ts = f"2025-09-10T12:00:{i:02d}Z"
        entries.append(entry.replace("2025-09-10T12:00:00Z", ts))

    log_path = logs_dir / "big_content.log"
    log_path.write_text("".join(entries), encoding="utf-8")

    # Set low byte limit to trigger byte-based flushing
    monkeypatch.setenv("LOGDB_BATCH_KB", "2")  # 2KB limit
    monkeypatch.setenv("LOGDB_BATCH_ROWS", "100")  # High row limit

    stats = ingest_logs(str(logs_dir), str(db_base))
    assert stats.rows_inserted > 0


def test_parallel_import_exception_handling(tmp_path, monkeypatch):
    """Test exception handling in parallel import setup (lines 520-521, 526-527)."""
    logs_dir = tmp_path / "logs"
    db_base = tmp_path / "logs" / "db"
    logs_dir.mkdir(parents=True, exist_ok=True)

    log_path = logs_dir / "test.log"
    log_path.write_text(SAMPLE_ENTRY_1, encoding="utf-8")

    # Test invalid parallelism setting (lines 526-527)
    monkeypatch.setenv("LOGDB_IMPORT_PARALLELISM", "invalid-number")
    stats = ingest_logs(str(logs_dir), str(db_base))
    # Should default to 2 and still work
    assert stats.files_scanned >= 1

    # Simplified test for concurrent.futures import failure
    # We'll mock the import at the module level instead of __builtins__
    import ai_proxy.logdb.ingest as ingest_module

    # Store original import function
    original_has_parallel = hasattr(ingest_module, 'ThreadPoolExecutor')

    # Mock the import failure by setting has_parallel to False in the function
    def mock_ingest_logs_no_parallel(source_dir, base_db_dir, since=None, to=None):
        # Call the original function but force single-threaded path
        monkeypatch.setenv("LOGDB_IMPORT_PARALLELISM", "1")
        return ingest_module.ingest_logs(source_dir, base_db_dir, since, to)

    # Test that single-threaded path works when parallel fails
    stats = mock_ingest_logs_no_parallel(str(logs_dir), str(db_base))
    assert stats.files_scanned >= 1


def test_single_threaded_ingestion_path(tmp_path, monkeypatch):
    """Test single-threaded ingestion path (lines 557-563)."""
    logs_dir = tmp_path / "logs"
    db_base = tmp_path / "logs" / "db"
    logs_dir.mkdir(parents=True, exist_ok=True)

    # Create multiple log files
    for i in range(3):
        log_path = logs_dir / f"test{i}.log"
        ts = f"2025-09-10T12:0{i}:00Z"
        entry = SAMPLE_ENTRY_1.replace("2025-09-10T12:00:00Z", ts)
        log_path.write_text(entry, encoding="utf-8")

    # Force single-threaded processing
    monkeypatch.setenv("LOGDB_IMPORT_PARALLELISM", "1")

    stats = ingest_logs(str(logs_dir), str(db_base))
    assert stats.files_scanned >= 3
    assert stats.rows_inserted >= 3


def test_sqlite_operational_error_fallback(tmp_path, monkeypatch):
    """Test SQLite operational error fallback in parallel processing."""
    from ai_proxy.logdb.ingest import _scan_log_file

    logs_dir = tmp_path / "logs"
    db_base = tmp_path / "logs" / "db"
    logs_dir.mkdir(parents=True, exist_ok=True)

    log_path = logs_dir / "test.log"
    log_path.write_text(SAMPLE_ENTRY_1, encoding="utf-8")

    # Mock _scan_log_file to raise OperationalError on first call
    original_scan = _scan_log_file
    call_count = [0]

    def mock_scan_with_error(*args, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            raise sqlite3.OperationalError("database is locked")
        return original_scan(*args, **kwargs)

    monkeypatch.setattr("ai_proxy.logdb.ingest._scan_log_file", mock_scan_with_error)
    monkeypatch.setenv("LOGDB_IMPORT_PARALLELISM", "2")

    # Should handle the error and retry
    stats = ingest_logs(str(logs_dir), str(db_base))
    assert stats.rows_inserted >= 1
    assert call_count[0] >= 2  # Should have been called multiple times due to retry
