import json
import os
import tarfile

from ai_proxy.logdb.bundle import create_bundle, verify_bundle
from tests.unit.shared.bundle_fixtures import (
    create_sample_partition,
    create_bundle_path,
    create_raw_logs_structure,
    create_test_bundle,
)


def test_bundle_create_and_verify_ok(tmp_path):
    """Test basic bundle creation and verification."""
    bundle_path, base_db_dir, date = create_test_bundle(tmp_path)
    assert os.path.isfile(bundle_path)
    assert verify_bundle(bundle_path) is True


def test_bundle_create_with_include_raw_and_metadata(tmp_path):
    """Test bundle creation with raw logs inclusion."""
    base_db_dir, date = create_sample_partition(tmp_path)
    raw_dir, _ = create_raw_logs_structure(tmp_path)
    bundle_path = create_bundle_path(tmp_path, "with_raw.tgz")

    bundle_path = create_bundle(
        base_db_dir=base_db_dir,
        since=date,
        to=date,
        out_path=str(bundle_path),
        include_raw=True,
        raw_logs_dir=raw_dir,
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
    """Test raw logs date filtering and env default behavior."""
    base_db_dir, date = create_sample_partition(tmp_path)
    raw_dir, _ = create_raw_logs_structure(tmp_path)
    bundle_path = create_bundle_path(tmp_path, "env-raw.tgz")

    # Set mtime for files: in-range on 'date', out-of-range one day before
    import datetime
    in_range = os.path.join(raw_dir, "app.log")
    out_range = os.path.join(raw_dir, "service.log.1")

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
            str(bundle_path),
            "--db",
            base_db_dir,
            "--raw",
            raw_dir,
        ]
    )
    assert rc == 0

    # Verify only in-range raw included
    with tarfile.open(bundle_path, "r:gz") as tar:
        names = [m.name for m in tar.getmembers() if m.isfile()]
        raw_names = [n for n in names if n.startswith("raw/")]
        # Only one raw file should be included
        assert len(raw_names) == 1 and raw_names[0].endswith("app.log")


def test_bundle_metadata_files_count_matches_tar(tmp_path):
    """Test that metadata files count matches actual tar contents."""
    bundle_path, base_db_dir, date = create_test_bundle(tmp_path)

    # Count entries in tar under db/ and compare to metadata files entries
    with tarfile.open(bundle_path, "r:gz") as tar:
        meta = json.loads(tar.extractfile("metadata.json").read().decode("utf-8"))  # type: ignore[arg-type]
        files_meta = [x for x in meta.get("files", []) if isinstance(x, dict)]
        db_members = [
            m for m in tar.getmembers() if m.isfile() and m.name.startswith("db/")
        ]
    assert len(files_meta) == len(db_members)


def test_cli_bundle_create_server_id_from_file(monkeypatch, tmp_path):
    """Test bundle create reads server_id from .server_id file."""
    from ai_proxy.logdb import cli as logdb_cli

    # Create sample partition
    base_db_dir, date = create_sample_partition(tmp_path)

    # Create .server_id file in db directory
    server_id_file = tmp_path / "logs" / "db" / ".server_id"
    server_id_file.write_text("test-server-from-file\n")

    bundle_path = create_bundle_path(tmp_path, "server_id_test.tgz")

    # Mock create_bundle to capture the server_id parameter
    original_create = create_bundle
    captured_server_id = None

    def mock_create_bundle(**kwargs):
        nonlocal captured_server_id
        captured_server_id = kwargs.get('server_id')
        return str(bundle_path)

    monkeypatch.setattr("ai_proxy.logdb.cli.commands.create_bundle", mock_create_bundle)

    rc = logdb_cli.main([
        "bundle", "create",
        "--since", date.strftime("%Y-%m-%d"),
        "--to", date.strftime("%Y-%m-%d"),
        "--out", str(bundle_path),
        "--db", base_db_dir,
    ])

    assert rc == 0
    assert captured_server_id == "test-server-from-file"


def test_cli_bundle_create_server_id_env_override(monkeypatch, tmp_path):
    """Test bundle create uses LOGDB_SERVER_ID env var over file."""
    from ai_proxy.logdb import cli as logdb_cli

    # Create sample partition
    base_db_dir, date = create_sample_partition(tmp_path)

    # Create .server_id file
    server_id_file = tmp_path / "logs" / "db" / ".server_id"
    server_id_file.write_text("from-file\n")

    # Set env var
    monkeypatch.setenv("LOGDB_SERVER_ID", "from-env")

    bundle_path = create_bundle_path(tmp_path, "server_id_env.tgz")

    # Mock create_bundle to capture the server_id parameter
    captured_server_id = None

    def mock_create_bundle(**kwargs):
        nonlocal captured_server_id
        captured_server_id = kwargs.get('server_id')
        return str(bundle_path)

    monkeypatch.setattr("ai_proxy.logdb.cli.commands.create_bundle", mock_create_bundle)

    rc = logdb_cli.main([
        "bundle", "create",
        "--since", date.strftime("%Y-%m-%d"),
        "--to", date.strftime("%Y-%m-%d"),
        "--out", str(bundle_path),
        "--db", base_db_dir,
    ])

    assert rc == 0
    assert captured_server_id == "from-env"


def test_collect_db_files_basic(tmp_path):
    """Test _collect_db_files collects database files in date range."""
    from ai_proxy.logdb.bundle import _collect_db_files
    import datetime as dt

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
        import sqlite3
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
