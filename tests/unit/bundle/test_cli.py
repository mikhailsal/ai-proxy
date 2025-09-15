import os

from ai_proxy.logdb.bundle import _collect_raw_logs


def test_collect_raw_logs_file_not_found_during_walk(tmp_path):
    """Test _collect_raw_logs handles FileNotFoundError during os.stat."""
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
