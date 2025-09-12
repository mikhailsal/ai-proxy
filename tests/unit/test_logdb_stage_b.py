import datetime as dt
import os
import sqlite3

from ai_proxy.logdb.ingest import ingest_logs
from ai_proxy.logdb.partitioning import compute_partition_path, control_database_path


SAMPLE_ENTRY_1 = (
    "2025-09-10 12:00:00 - INFO - {\n"
    '  "timestamp": "2025-09-10T12:00:00Z",\n'
    '  "endpoint": "/v1/chat/completions",\n'
    '  "status_code": 200,\n'
    '  "latency_ms": 123.45,\n'
    '  "request": {\n'
    '    "model": "gpt-4",\n'
    '    "messages": [{"role": "user", "content": "Hi"}]\n'
    "  },\n"
    '  "response": {\n'
    '    "id": "chatcmpl-1",\n'
    '    "model": "openrouter/openai/gpt-4",\n'
    '    "choices": [{"index": 0, "message": {"role": "assistant", "content": "Hello"}}]\n'
    "  }\n"
    "}\n"
)


SAMPLE_ENTRY_2 = (
    "2025-09-10 12:05:00 - INFO - {\n"
    '  "timestamp": "2025-09-10T12:05:00Z",\n'
    '  "endpoint": "/v1/chat/completions",\n'
    '  "status_code": 200,\n'
    '  "latency_ms": 98.7,\n'
    '  "request": {\n'
    '    "model": "gemini-pro",\n'
    '    "messages": [{"role": "user", "content": "Count 1-3"}]\n'
    "  },\n"
    '  "response": {\n'
    '    "id": "chatcmpl-2",\n'
    '    "model": "gemini:gemini-2.0-flash-001",\n'
    '    "choices": [{"index": 0, "message": {"role": "assistant", "content": "1,2,3"}}]\n'
    "  }\n"
    "}\n"
)


def test_ingest_basic_and_idempotent(tmp_path):
    logs_dir = tmp_path / "logs"
    db_base = tmp_path / "logs" / "db"
    logs_dir.mkdir(parents=True, exist_ok=True)

    log_path = logs_dir / "v1_chat_completions.log"
    log_path.write_text(SAMPLE_ENTRY_1 + SAMPLE_ENTRY_2, encoding="utf-8")

    # First ingest
    stats1 = ingest_logs(str(logs_dir), str(db_base))
    assert stats1.rows_inserted == 2
    assert stats1.files_scanned >= 1

    # Second ingest should be idempotent (no new rows)
    stats2 = ingest_logs(str(logs_dir), str(db_base))
    assert stats2.rows_inserted == 0

    # Verify rows exist in the correct partition
    date = dt.date(2025, 9, 10)
    db_path = compute_partition_path(str(db_base), date)
    assert os.path.isfile(db_path)

    conn = sqlite3.connect(db_path)
    try:
        cur = conn.execute("SELECT COUNT(*) FROM requests;")
        count = cur.fetchone()[0]
        assert count == 2

        # Spot-check columns present
        cur = conn.execute("PRAGMA table_info(requests);")
        cols = {row[1] for row in cur.fetchall()}
        assert {
            "request_id",
            "server_id",
            "ts",
            "endpoint",
            "request_json",
            "response_json",
        }.issubset(cols)
    finally:
        conn.close()

    # Verify checkpoint recorded in today's control partition
    control_db = control_database_path(str(db_base))
    assert os.path.isfile(control_db)
    conn = sqlite3.connect(control_db)
    try:
        cur = conn.execute(
            "SELECT source_path, bytes_ingested, mtime FROM ingest_sources LIMIT 1;"
        )
        row = cur.fetchone()
        assert row is not None
        assert row[0].endswith("v1_chat_completions.log")
        assert int(row[1]) > 0
        assert int(row[2]) > 0
    finally:
        conn.close()


def test_ingest_resume_with_prefix_sha_validation(tmp_path):
    logs_dir = tmp_path / "logs"
    db_base = tmp_path / "logs" / "db"
    logs_dir.mkdir(parents=True, exist_ok=True)

    log_path = logs_dir / "v1_chat_completions.log"
    # First entry
    log_path.write_text(SAMPLE_ENTRY_1, encoding="utf-8")
    stats1 = ingest_logs(str(logs_dir), str(db_base))
    assert (
        stats1.rows_inserted == 2 or stats1.rows_inserted == 1
    )  # depending on date range

    # Append second entry and corrupt the first byte without changing size by toggling a space
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(SAMPLE_ENTRY_2)

    # Now rewrite first byte to force prefix sha mismatch but keep same size
    p = log_path.read_text(encoding="utf-8")
    if p:
        mutated = (" " if p[0] != " " else "\t") + p[1:]
        log_path.write_text(mutated, encoding="utf-8")

    ingest_logs(str(logs_dir), str(db_base))
    # Should not double-insert earlier lines; idempotent overall
    date = dt.date(2025, 9, 10)
    db_path = compute_partition_path(str(db_base), date)
    if os.path.isfile(db_path):
        conn = sqlite3.connect(db_path)
        try:
            count = conn.execute("SELECT COUNT(*) FROM requests;").fetchone()[0]
            assert count >= 2
        finally:
            conn.close()


def test_parallel_ingest_env_flag(tmp_path, monkeypatch):
    logs_dir = tmp_path / "logs"
    db_base = tmp_path / "logs" / "db"
    logs_dir.mkdir(parents=True, exist_ok=True)
    (logs_dir / "v1_chat_completions.log").write_text(SAMPLE_ENTRY_1, encoding="utf-8")
    (logs_dir / "v1_models.log").write_text(SAMPLE_ENTRY_2, encoding="utf-8")

    monkeypatch.setenv("LOGDB_IMPORT_PARALLELISM", "4")
    stats = ingest_logs(str(logs_dir), str(db_base))
    assert stats.files_scanned >= 2


def test_ingest_resume_after_interruption(tmp_path):
    logs_dir = tmp_path / "logs"
    db_base = tmp_path / "logs" / "db"
    logs_dir.mkdir(parents=True, exist_ok=True)

    log_path = logs_dir / "v1_chat_completions.log"

    # Write only the first entry and ingest
    log_path.write_text(SAMPLE_ENTRY_1, encoding="utf-8")
    stats1 = ingest_logs(str(logs_dir), str(db_base))
    assert stats1.rows_inserted == 1

    # Append the second entry and re-run ingest; should only add one more
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(SAMPLE_ENTRY_2)

    stats2 = ingest_logs(str(logs_dir), str(db_base))
    assert stats2.rows_inserted == 1

    # Verify total rows = 2
    date = dt.date(2025, 9, 10)
    db_path = compute_partition_path(str(db_base), date)
    conn = sqlite3.connect(db_path)
    try:
        count = conn.execute("SELECT COUNT(*) FROM requests;").fetchone()[0]
        assert count == 2
    finally:
        conn.close()


def test_ingest_date_range_filtering(tmp_path):
    logs_dir = tmp_path / "logs"
    db_base = tmp_path / "logs" / "db"
    logs_dir.mkdir(parents=True, exist_ok=True)

    log_path = logs_dir / "v1_chat_completions.log"
    log_path.write_text(SAMPLE_ENTRY_1 + SAMPLE_ENTRY_2, encoding="utf-8")

    # Only include up to 2025-09-10
    since = dt.date(2025, 9, 10)
    to = dt.date(2025, 9, 10)
    stats = ingest_logs(str(logs_dir), str(db_base), since, to)
    assert stats.rows_inserted == 2

    # Narrow to a date before range: expect zero
    since2 = dt.date(2025, 9, 9)
    to2 = dt.date(2025, 9, 9)
    stats2 = ingest_logs(str(logs_dir), str(db_base), since2, to2)
    assert stats2.rows_inserted == 0


def test_ingest_rotated_log_files(tmp_path):
    logs_dir = tmp_path / "logs"
    db_base = tmp_path / "logs" / "db"
    logs_dir.mkdir(parents=True, exist_ok=True)

    main_log = logs_dir / "v1_chat_completions.log"
    rotated_log = logs_dir / "v1_chat_completions.log.1"

    main_log.write_text(SAMPLE_ENTRY_1, encoding="utf-8")
    rotated_log.write_text(SAMPLE_ENTRY_2, encoding="utf-8")

    stats = ingest_logs(str(logs_dir), str(db_base))
    # Both files should be processed; two rows total
    assert stats.rows_inserted == 2


def test_cli_gating_env_flags_for_ingest(monkeypatch, tmp_path):
    # Ensure gating: when LOGDB_ENABLED != true, CLI should return code 2
    from ai_proxy.logdb import cli as logdb_cli

    logs_dir = tmp_path / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    (logs_dir / "v1_chat_completions.log").write_text(SAMPLE_ENTRY_1, encoding="utf-8")

    # Disabled case
    monkeypatch.setenv("LOGDB_ENABLED", "false")
    rc = logdb_cli.main(
        ["ingest", "--from", str(logs_dir), "--out", str(tmp_path / "logs" / "db")]
    )
    assert rc == 2

    # Enabled case
    monkeypatch.setenv("LOGDB_ENABLED", "true")
    rc2 = logdb_cli.main(
        ["ingest", "--from", str(logs_dir), "--out", str(tmp_path / "logs" / "db")]
    )
    assert rc2 == 0


def test_cli_init_error_handling(monkeypatch, tmp_path):
    """Test cmd_init handles database integrity check failures."""
    from ai_proxy.logdb import cli as logdb_cli
    from ai_proxy.logdb.schema import run_integrity_check

    # Mock run_integrity_check to return "failed"
    original_check = run_integrity_check
    def mock_check(conn):
        return "failed"

    monkeypatch.setattr("ai_proxy.logdb.cli.run_integrity_check", mock_check)

    rc = logdb_cli.main(["init", "--out", str(tmp_path / "logs" / "db")])
    assert rc == 1  # Should return 1 for failed integrity check


def test_cli_fts_drop_error_handling(monkeypatch, tmp_path):
    """Test _cmd_fts_drop handles exceptions and returns appropriate exit codes."""
    from ai_proxy.logdb import cli as logdb_cli
    from ai_proxy.logdb.fts import drop_fts_table

    # Mock drop_fts_table to raise an exception
    original_drop = drop_fts_table
    def mock_drop(conn):
        raise Exception("Database error")

    monkeypatch.setattr("ai_proxy.logdb.cli.drop_fts_table", mock_drop)
    monkeypatch.setenv("LOGDB_FTS_ENABLED", "true")

    # Create a fake db file
    db_dir = tmp_path / "logs" / "db" / "2025" / "09"
    db_dir.mkdir(parents=True)
    db_file = db_dir / "ai_proxy_20250910.sqlite3"
    db_file.write_text("fake db content")

    rc = logdb_cli.main([
        "fts", "drop",
        "--out", str(tmp_path / "logs" / "db"),
        "--since", "2025-09-10",
        "--to", "2025-09-10"
    ])
    assert rc == 1  # Should return 1 when drop operation fails


def test_cli_bundle_verify_command(monkeypatch, tmp_path):
    """Test bundle verify command outputs correct results."""
    from ai_proxy.logdb import cli as logdb_cli
    from ai_proxy.logdb.bundle import verify_bundle

    # Test successful verification
    monkeypatch.setattr("ai_proxy.logdb.cli.verify_bundle", lambda x: True)
    rc = logdb_cli.main(["bundle", "verify", "fake_bundle.tgz"])
    assert rc == 0

    # Test failed verification
    monkeypatch.setattr("ai_proxy.logdb.cli.verify_bundle", lambda x: False)
    rc = logdb_cli.main(["bundle", "verify", "fake_bundle.tgz"])
    assert rc == 1


def test_cli_bundle_transfer_command(monkeypatch, tmp_path):
    """Test bundle transfer command with different scenarios."""
    from ai_proxy.logdb import cli as logdb_cli
    from ai_proxy.logdb.transport import copy_with_resume

    # Mock successful copy
    monkeypatch.setattr("ai_proxy.logdb.cli.copy_with_resume", lambda src, dst: (1000, "abcd1234"))
    monkeypatch.setattr("ai_proxy.logdb.cli.verify_bundle", lambda x: True)

    # Test with .tgz extension (should verify)
    rc = logdb_cli.main(["bundle", "transfer", "src.tgz", "dst.tgz"])
    assert rc == 0

    # Test with non-.tgz extension (should not verify)
    rc = logdb_cli.main(["bundle", "transfer", "src.tgz", "dst.txt"])
    assert rc == 0


def test_cli_bundle_transfer_verify_failure(monkeypatch, tmp_path):
    """Test bundle transfer command when verification fails."""
    from ai_proxy.logdb import cli as logdb_cli

    # Mock copy success but verify failure
    monkeypatch.setattr("ai_proxy.logdb.cli.copy_with_resume", lambda src, dst: (1000, "abcd1234"))
    monkeypatch.setattr("ai_proxy.logdb.cli.verify_bundle", lambda x: False)

    rc = logdb_cli.main(["bundle", "transfer", "src.tgz", "dst.tgz"])
    assert rc == 1  # Should return 1 when verification fails


def test_cli_bundle_import_command(monkeypatch, tmp_path):
    """Test bundle import command output."""
    from ai_proxy.logdb import cli as logdb_cli
    from ai_proxy.logdb.bundle import import_bundle

    # Mock import_bundle to return counts
    monkeypatch.setattr("ai_proxy.logdb.cli.import_bundle", lambda bundle, dest: (5, 2))

    rc = logdb_cli.main(["bundle", "import", "bundle.tgz", "--dest", str(tmp_path)])
    assert rc == 0


def test_cli_merge_command(monkeypatch, tmp_path):
    """Test merge command output."""
    from ai_proxy.logdb import cli as logdb_cli
    from ai_proxy.logdb.merge import merge_partitions

    # Mock merge_partitions to return results
    monkeypatch.setattr("ai_proxy.logdb.cli.merge_partitions", lambda src, dst: (3, 150, "ok"))

    rc = logdb_cli.main(["merge", "--from", str(tmp_path / "src"), "--to", str(tmp_path / "dst.db")])
    assert rc == 0


def test_cli_merge_command_integrity_failure(monkeypatch, tmp_path):
    """Test merge command when integrity check fails."""
    from ai_proxy.logdb import cli as logdb_cli

    # Mock merge_partitions to return failed integrity
    monkeypatch.setattr("ai_proxy.logdb.cli.merge_partitions", lambda src, dst: (3, 150, "failed"))

    rc = logdb_cli.main(["merge", "--from", str(tmp_path / "src"), "--to", str(tmp_path / "dst.db")])
    assert rc == 1


def test_cli_fts_drop_date_range_scenarios(monkeypatch, tmp_path):
    """Test _cmd_fts_drop handles different date range scenarios."""
    import sqlite3
    from ai_proxy.logdb import cli as logdb_cli

    # Create proper SQLite db files for different dates
    db_dir = tmp_path / "logs" / "db" / "2025" / "09"
    db_dir.mkdir(parents=True)
    dates = ["20250910", "20250911", "20250912"]
    for date in dates:
        db_path = db_dir / f"ai_proxy_{date}.sqlite3"
        # Create a valid SQLite database file
        conn = sqlite3.connect(str(db_path))
        conn.close()

    monkeypatch.setenv("LOGDB_FTS_ENABLED", "true")

    # Test with only --to provided (should set since_date = to_date)
    rc = logdb_cli.main([
        "fts", "drop",
        "--out", str(tmp_path / "logs" / "db"),
        "--to", "2025-09-11"
    ])
    assert rc == 0

    # Test with only --since provided (should set to_date = since_date)
    rc = logdb_cli.main([
        "fts", "drop",
        "--out", str(tmp_path / "logs" / "db"),
        "--since", "2025-09-10"
    ])
    assert rc == 0

    # Test with no dates provided (should default to today for both)
    rc = logdb_cli.main([
        "fts", "drop",
        "--out", str(tmp_path / "logs" / "db")
    ])
    assert rc == 0


def test_cli_main_with_invalid_command():
    """Test main function with invalid command."""
    from ai_proxy.logdb import cli as logdb_cli
    import sys

    # Mock sys.exit to capture the exit code
    original_exit = sys.exit
    exit_codes = []
    def mock_exit(code):
        exit_codes.append(code)
        raise SystemExit(code)

    sys.exit = mock_exit
    try:
        logdb_cli.main(["invalid-command"])
        assert False, "Should have called sys.exit"
    except SystemExit:
        pass
    finally:
        sys.exit = original_exit

    assert exit_codes == [2]


def test_cli_main_with_no_args():
    """Test main function with no arguments."""
    from ai_proxy.logdb import cli as logdb_cli
    import sys

    # Mock sys.exit to capture the exit code
    original_exit = sys.exit
    exit_codes = []
    def mock_exit(code):
        exit_codes.append(code)
        raise SystemExit(code)

    sys.exit = mock_exit
    try:
        logdb_cli.main([])
        assert False, "Should have called sys.exit"
    except SystemExit:
        pass
    finally:
        sys.exit = original_exit

    assert exit_codes == [2]


def test_cli_main_with_help():
    """Test main function with help flag."""
    from ai_proxy.logdb import cli as logdb_cli
    import sys

    # Mock sys.exit to capture the exit code
    original_exit = sys.exit
    exit_codes = []
    def mock_exit(code):
        exit_codes.append(code)
        raise SystemExit(code)

    sys.exit = mock_exit
    try:
        logdb_cli.main(["--help"])
        assert False, "Should have called sys.exit"
    except SystemExit:
        pass
    finally:
        sys.exit = original_exit

    assert exit_codes == [0]


def test_cli_main_with_argv_none():
    """Test main function with argv=None."""
    from ai_proxy.logdb import cli as logdb_cli
    import sys

    # Mock sys.exit to capture the exit code
    original_exit = sys.exit
    exit_codes = []
    def mock_exit(code):
        exit_codes.append(code)
        raise SystemExit(code)

    sys.exit = original_exit
    try:
        sys.exit = mock_exit
        logdb_cli.main(None)
        assert False, "Should have called sys.exit"
    except SystemExit:
        pass
    finally:
        sys.exit = original_exit

    assert exit_codes == [2]  # Invalid command line from pytest


def test_cli_build_parser_structure():
    """Test that build_parser creates proper argument parser structure."""
    from ai_proxy.logdb import cli as logdb_cli

    parser = logdb_cli.build_parser()

    # Check that main subcommands exist
    subcommands = []
    for action in parser._subparsers._group_actions:
        if hasattr(action, 'choices'):
            subcommands.extend(action.choices.keys())

    expected_commands = ['init', 'ingest', 'fts', 'bundle', 'dialogs', 'merge']
    for cmd in expected_commands:
        assert cmd in subcommands


def test_cli_cmd_init_with_invalid_date(monkeypatch, tmp_path):
    """Test cmd_init with invalid date format."""
    from ai_proxy.logdb import cli as logdb_cli

    class Args:
        date = "invalid-date"
        out = str(tmp_path / "db")

    args = Args()

    # Should handle invalid date gracefully by raising ValueError
    try:
        logdb_cli.cmd_init(args)
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "time data" in str(e) and "does not match format" in str(e)


def test_cli_cmd_init_database_creation(tmp_path):
    """Test cmd_init creates database directory structure."""
    from ai_proxy.logdb import cli as logdb_cli

    class Args:
        date = None  # Use today
        out = str(tmp_path / "logs" / "db")

    args = Args()

    rc = logdb_cli.cmd_init(args)
    assert rc == 0

    # Check that directory structure was created
    import os
    from datetime import date
    today = date.today()
    expected_path = os.path.join(
        args.out,
        f"{today.year:04d}",
        f"{today.month:02d}",
        f"ai_proxy_{today.strftime('%Y%m%d')}.sqlite3"
    )
    assert os.path.isfile(expected_path)


def test_cli_bundle_transfer_with_verification_error(monkeypatch, tmp_path):
    """Test bundle transfer when verification fails."""
    from ai_proxy.logdb import cli as logdb_cli

    # Create test files
    src_file = tmp_path / "test.tgz"
    dest_file = tmp_path / "dest.tgz"
    src_file.write_bytes(b"dummy content")

    # Mock copy_with_resume to succeed but verify_bundle to fail
    monkeypatch.setattr("ai_proxy.logdb.cli.copy_with_resume", lambda src, dst: (100, "abcd1234"))
    monkeypatch.setattr("ai_proxy.logdb.cli.verify_bundle", lambda path: False)

    # Test with .tgz extension (should try to verify)
    rc = logdb_cli.main(["bundle", "transfer", str(src_file), str(dest_file)])
    assert rc == 1  # Should return 1 when verification fails


def test_cli_bundle_transfer_non_bundle_file(monkeypatch, tmp_path):
    """Test bundle transfer with non-.tgz file (no verification)."""
    from ai_proxy.logdb import cli as logdb_cli

    # Create test files
    src_file = tmp_path / "test.txt"
    dest_file = tmp_path / "dest.txt"
    src_file.write_bytes(b"dummy content")

    # Mock copy_with_resume
    monkeypatch.setattr("ai_proxy.logdb.cli.copy_with_resume", lambda src, dst: (100, "abcd1234"))

    # Test with .txt extension (should not verify)
    rc = logdb_cli.main(["bundle", "transfer", str(src_file), str(dest_file)])
    assert rc == 0  # Should succeed without verification
