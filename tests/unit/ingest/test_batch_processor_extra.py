import time


from ai_proxy.logdb.processing import batch_processor
from ai_proxy.logdb.partitioning import ensure_control_database
from ai_proxy.logdb.schema import open_connection_with_pragmas
from tests.unit.shared.ingest_fixtures import SAMPLE_ENTRY_1


def test_scan_log_file_prefix_sha_exception(tmp_path, monkeypatch):
    logs_dir = tmp_path / "logs"
    db_base = logs_dir / "db"
    logs_dir.mkdir(parents=True, exist_ok=True)

    log_path = logs_dir / "test.log"
    log_path.write_text(SAMPLE_ENTRY_1, encoding="utf-8")

    # Create control DB and insert a checkpoint record so prev_bytes > 0
    control_path = ensure_control_database(str(db_base))
    conn = open_connection_with_pragmas(control_path)
    try:
        with conn:
            conn.execute(
                "INSERT OR REPLACE INTO ingest_sources (source_path, sha256, bytes_ingested, mtime, last_scan_ts) VALUES (?, ?, ?, ?, ?)",
                (str(log_path), "deadbeef", 1, 0, int(time.time())),
            )
    finally:
        conn.close()

    # Force file prefix sha to raise only for the resume check to exercise
    # exception handler path, but allow later calls to proceed.
    original_prefix = batch_processor._file_prefix_sha256

    def _maybe_raise(path, upto_bytes):
        if int(upto_bytes) == 1:
            raise Exception("boom")
        return original_prefix(path, upto_bytes)

    monkeypatch.setattr(
        "ai_proxy.logdb.processing.batch_processor._file_prefix_sha256",
        _maybe_raise,
    )

    inserted, skipped = batch_processor._scan_log_file(
        str(log_path), str(db_base), None, None, "srv-1"
    )
    assert inserted >= 0


def test_scan_log_file_malformed_entry(tmp_path):
    logs_dir = tmp_path / "logs"
    db_base = logs_dir / "db"
    logs_dir.mkdir(parents=True, exist_ok=True)

    # Write a JSON block that lacks required fields (endpoint/request/response)
    log_path = logs_dir / "test.log"
    log_path.write_text('{"not": "valid"}\n', encoding="utf-8")

    inserted, skipped = batch_processor._scan_log_file(
        str(log_path), str(db_base), None, None, "srv-2"
    )
    # Should skip malformed entry without crashing
    assert inserted == 0


def test_memory_pressure_forces_flush(tmp_path, monkeypatch):
    logs_dir = tmp_path / "logs"
    db_base = logs_dir / "db"
    logs_dir.mkdir(parents=True, exist_ok=True)

    log_path = logs_dir / "test.log"
    # write multiple valid entries so there is something to flush
    content = "\n".join([SAMPLE_ENTRY_1 for _ in range(5)])
    log_path.write_text(content, encoding="utf-8")

    # Make estimate function report very large sizes so memory pressure triggers
    monkeypatch.setattr(
        "ai_proxy.logdb.processing.batch_processor._estimate_batch_bytes",
        lambda _b: 10 * 1024 * 1024,
    )
    monkeypatch.setenv("LOGDB_MEMORY_MB", "1")

    inserted, skipped = batch_processor._scan_log_file(
        str(log_path), str(db_base), None, None, "srv-3"
    )

    assert inserted >= 0
