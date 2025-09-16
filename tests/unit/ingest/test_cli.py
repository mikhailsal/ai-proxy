import sqlite3
import logging
from ai_proxy.logdb import cli as logdb_cli
from tests.unit.shared.ingest_fixtures import SAMPLE_ENTRY_1


def test_cli_gating_env_flags_for_ingest(monkeypatch, tmp_path):
    # Ensure gating: when LOGDB_ENABLED != true, CLI should return code 2
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


def test_cli_init_error_handling(tmp_path, monkeypatch):
    """Test cmd_init handles database integrity check failures."""
    # Mock run_integrity_check to return "failed"

    def mock_check(conn):
        return "corrupt"

    monkeypatch.setattr("ai_proxy.logdb.cli.commands.run_integrity_check", mock_check)

    rc = logdb_cli.main(["init", "--out", str(tmp_path / "logs" / "db")])
    assert rc == 1  # Should return 1 for failed integrity check


def test_cli_fts_drop_error_handling(tmp_path, monkeypatch):
    """Test _cmd_fts_drop handles exceptions and returns appropriate exit codes."""
    # Mock drop_fts_table to raise an exception

    def mock_drop(conn):
        raise ValueError("drop failed")

    monkeypatch.setattr("ai_proxy.logdb.cli.commands.drop_fts_table", mock_drop)
    monkeypatch.setenv("LOGDB_FTS_ENABLED", "true")

    # Create a fake db file
    db_dir = tmp_path / "logs" / "db" / "2025" / "09"
    db_dir.mkdir(parents=True)
    db_file = db_dir / "ai_proxy_20250910.sqlite3"
    db_file.write_text("fake db content")

    rc = logdb_cli.main(
        [
            "fts",
            "drop",
            "--out",
            str(tmp_path / "logs" / "db"),
            "--since",
            "2025-09-10",
            "--to",
            "2025-09-10",
        ]
    )
    assert rc == 1  # Should return 1 when drop operation fails


def test_cli_bundle_verify_command(caplog, monkeypatch):
    """Test bundle verify command outputs correct results."""
    # Test successful verification
    monkeypatch.setattr("ai_proxy.logdb.cli.commands.verify_bundle", lambda x: True)
    rc = logdb_cli.main(["bundle", "verify", "fake_bundle.tgz"])
    assert rc == 0

    # Test failed verification
    monkeypatch.setattr("ai_proxy.logdb.cli.commands.verify_bundle", lambda x: False)
    rc = logdb_cli.main(["bundle", "verify", "fake_bundle.tgz"])
    assert rc == 1


def test_cli_bundle_transfer_command(caplog, monkeypatch):
    """Test bundle transfer command with different scenarios."""
    # Mock successful copy
    monkeypatch.setattr(
        "ai_proxy.logdb.cli.commands.copy_with_resume",
        lambda src, dst: (1000, "abcd1234"),
    )
    monkeypatch.setattr("ai_proxy.logdb.cli.commands.verify_bundle", lambda x: True)

    # Test with .tgz extension (should verify)
    rc = logdb_cli.main(["bundle", "transfer", "src.tgz", "dst.tgz"])
    assert rc == 0

    # Test with non-.tgz extension (should not verify)
    rc = logdb_cli.main(["bundle", "transfer", "src.tgz", "dst.txt"])
    assert rc == 0


def test_cli_bundle_transfer_verify_failure(caplog, monkeypatch):
    """Test bundle transfer command when verification fails."""
    # Mock copy success but verify failure
    monkeypatch.setattr(
        "ai_proxy.logdb.cli.commands.copy_with_resume",
        lambda src, dst: (1000, "abcd1234"),
    )
    monkeypatch.setattr("ai_proxy.logdb.cli.commands.verify_bundle", lambda x: False)

    rc = logdb_cli.main(["bundle", "transfer", "src.tgz", "dst.tgz"])
    assert rc == 1  # Should return 1 when verification fails


def test_cli_bundle_import_command(tmp_path, caplog, monkeypatch):
    """Test bundle import command output."""

    # Mock import_bundle to return counts
    monkeypatch.setattr(
        "ai_proxy.logdb.cli.commands.import_bundle", lambda bundle, dest: (5, 2)
    )

    rc = logdb_cli.main(["bundle", "import", "bundle.tgz", "--dest", str(tmp_path)])
    assert rc == 0


def test_cli_merge_command(tmp_path, caplog, monkeypatch):
    """Test merge command output."""
    # Mock merge_partitions to return results
    monkeypatch.setattr(
        "ai_proxy.logdb.cli.commands.merge_partitions", lambda src, dst: (3, 150, "ok")
    )

    rc = logdb_cli.main(
        ["merge", "--from", str(tmp_path / "src"), "--to", str(tmp_path / "dst.db")]
    )
    assert rc == 0


def test_cli_merge_command_integrity_failure(tmp_path, monkeypatch):
    """Test merge command when integrity check fails."""
    # Mock merge_partitions to return failed integrity
    monkeypatch.setattr(
        "ai_proxy.logdb.cli.commands.merge_partitions",
        lambda src, dst: (3, 150, "failed"),
    )

    rc = logdb_cli.main(
        ["merge", "--from", str(tmp_path / "src"), "--to", str(tmp_path / "dst.db")]
    )
    assert rc == 1


def test_cli_fts_drop_date_range_scenarios(monkeypatch, tmp_path):
    """Test _cmd_fts_drop handles different date range scenarios."""
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
    rc = logdb_cli.main(
        ["fts", "drop", "--out", str(tmp_path / "logs" / "db"), "--to", "2025-09-11"]
    )
    assert rc == 0

    # Test with only --since provided (should set to_date = since_date)
    rc = logdb_cli.main(
        ["fts", "drop", "--out", str(tmp_path / "logs" / "db"), "--since", "2025-09-10"]
    )
    assert rc == 0

    # Test with no dates provided (should default to today for both)
    rc = logdb_cli.main(["fts", "drop", "--out", str(tmp_path / "logs" / "db")])
    assert rc == 0


def test_cli_main_with_invalid_command():
    """Test main function with invalid command."""
    # Mock sys.exit to capture the exit code
    import pytest

    with pytest.raises(SystemExit) as se:
        logdb_cli.main(["invalid-command"])
    assert se.value.code == 2


def test_cli_main_with_no_args():
    """Test main function with no arguments."""
    # Mock sys.exit to capture the exit code
    import pytest

    with pytest.raises(SystemExit) as se2:
        logdb_cli.main([])
    assert se2.value.code == 2


def test_cli_main_with_help():
    """Test main function with help flag."""
    # Mock sys.exit to capture the exit code
    import pytest

    with pytest.raises(SystemExit) as se3:
        logdb_cli.main(["--help"])
    assert se3.value.code == 0


def test_cli_main_with_argv_none():
    """Test main function with argv=None."""
    # Mock sys.exit to capture the exit code
    import pytest

    with pytest.raises(SystemExit) as se4:
        logdb_cli.main(None)
    assert se4.value.code == 2  # Invalid command line from pytest


def test_cli_build_parser_structure():
    """Test that build_parser creates proper argument parser structure."""
    parser = logdb_cli.build_parser()

    # Check that main subcommands exist
    subcommands = []
    for action in parser._subparsers._group_actions:
        if hasattr(action, "choices"):
            subcommands.extend(action.choices.keys())

    expected_commands = ["init", "ingest", "fts", "bundle", "dialogs", "merge"]
    for cmd in expected_commands:
        assert cmd in subcommands


def test_cli_cmd_init_with_invalid_date(monkeypatch, tmp_path):
    """Test cmd_init with invalid date format."""

    class Args:
        date = "invalid-date"
        out = str(tmp_path / "db")

    args = Args()

    # Should handle invalid date gracefully by raising ValueError
    import pytest

    with pytest.raises(ValueError) as ex:
        logdb_cli.cmd_init(args)
    assert "time data" in str(ex.value) and "does not match format" in str(ex.value)


def test_cli_cmd_init_database_creation(tmp_path):
    """Test cmd_init creates database directory structure."""

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
        f"ai_proxy_{today.strftime('%Y%m%d')}.sqlite3",
    )
    assert os.path.isfile(expected_path)


def test_cli_bundle_transfer_with_verification_error(monkeypatch, tmp_path, caplog):
    caplog.set_level(logging.INFO)
    src_file = tmp_path / "src.tgz"
    src_file.touch()
    dest_file = tmp_path / "dst.tgz"

    monkeypatch.setattr(
        "ai_proxy.logdb.cli.commands.copy_with_resume",
        lambda src, dst: (100, "abcd1234"),
    )
    monkeypatch.setattr("ai_proxy.logdb.cli.commands.verify_bundle", lambda path: False)

    # Test with .tgz extension (should try to verify)
    rc = logdb_cli.main(["bundle", "transfer", str(src_file), str(dest_file)])
    assert rc == 1  # Should return 1 when verification fails

    # Test with raise exception in verify
    def raise_exc(path):
        raise ValueError("verify error")

    monkeypatch.setattr("ai_proxy.logdb.cli.commands.verify_bundle", raise_exc)

    rc = logdb_cli.main(["bundle", "transfer", str(src_file), str(dest_file)])
    assert rc == 0  # Should succeed even if verification raises exception


def test_cli_bundle_transfer_non_bundle_file(tmp_path, caplog, monkeypatch):
    caplog.set_level(logging.INFO)

    # Create test files
    src_file = tmp_path / "test.txt"
    dest_file = tmp_path / "dest.txt"
    src_file.write_bytes(b"dummy content")

    # Mock copy_with_resume
    monkeypatch.setattr(
        "ai_proxy.logdb.cli.commands.copy_with_resume",
        lambda src, dst: (1000, "abcd1234"),
    )

    # Test with .txt extension (should not verify)
    rc = logdb_cli.main(["bundle", "transfer", str(src_file), str(dest_file)])
    assert rc == 0  # Should succeed without verification
