import datetime as dt
from fastapi.testclient import TestClient
from tests.unit.ui.test_models_helpers import _make_partition
import os


def test_requests_listing_cross_partitions_and_pagination(tmp_path, monkeypatch):
    # Prepare two daily partitions under logs/db/YYYY/MM
    base_dir = tmp_path / "logs" / "db"
    d1 = dt.date(2025, 9, 9)
    d2 = dt.date(2025, 9, 10)
    p1 = (
        base_dir
        / f"{d1.year:04d}"
        / f"{d1.month:02d}"
        / f"ai_proxy_{d1.strftime('%Y%m%d')}.sqlite3"
    )
    p2 = (
        base_dir
        / f"{d2.year:04d}"
        / f"{d2.month:02d}"
        / f"ai_proxy_{d2.strftime('%Y%m%d')}.sqlite3"
    )
    base_ts1 = int(dt.datetime(d1.year, d1.month, d1.day, 12, 0).timestamp())
    base_ts2 = int(dt.datetime(d2.year, d2.month, d2.day, 12, 0).timestamp())
    _make_partition(str(p1), rows=3, base_ts=base_ts1, start_id=0)
    _make_partition(str(p2), rows=2, base_ts=base_ts2, start_id=100)

    monkeypatch.setenv("LOGUI_API_KEYS", "user-key")
    monkeypatch.setenv("LOGUI_RATE_LIMIT_RPS", "1000")
    monkeypatch.setenv("LOGUI_DB_ROOT", str(base_dir))

    from ai_proxy_ui.main import app

    client = TestClient(app)

    r = client.get(
        "/ui/v1/requests",
        params={"since": str(d1), "to": str(d2), "limit": 3},
        headers={"Authorization": "Bearer user-key"},
    )
    assert r.status_code == 200
    data = r.json()
    assert len(data["items"]) == 3
    assert data["nextCursor"]
    ts_list = [it["ts"] for it in data["items"]]
    assert ts_list == sorted(ts_list, reverse=True)

    r2 = client.get(
        "/ui/v1/requests",
        params={
            "since": str(d1),
            "to": str(d2),
            "limit": 3,
            "cursor": data["nextCursor"],
        },
        headers={"Authorization": "Bearer user-key"},
    )
    assert r2.status_code == 200
    data2 = r2.json()
    assert len(data2["items"]) == 2
    assert data2["nextCursor"] is None


def test_requests_listing_with_corrupted_database(tmp_path, monkeypatch):
    """Test that requests listing handles corrupted database files gracefully."""
    base_dir = tmp_path / "logs" / "db"
    d1 = dt.date(2025, 9, 9)

    # Create a valid partition
    p1 = (
        base_dir
        / f"{d1.year:04d}"
        / f"{d1.month:02d}"
        / f"ai_proxy_{d1.strftime('%Y%m%d')}.sqlite3"
    )
    base_ts1 = int(dt.datetime(d1.year, d1.month, d1.day, 12, 0).timestamp())
    _make_partition(str(p1), rows=2, base_ts=base_ts1, start_id=0)

    # Create a corrupted database file
    p2 = (
        base_dir
        / f"{d1.year:04d}"
        / f"{d1.month:02d}"
        / f"ai_proxy_{(d1 + dt.timedelta(days=1)).strftime('%Y%m%d')}.sqlite3"
    )
    os.makedirs(os.path.dirname(p2), exist_ok=True)
    # Write invalid SQLite data
    with open(p2, "wb") as f:
        f.write(b"this is not a valid sqlite database file")

    monkeypatch.setenv("LOGUI_API_KEYS", "user-key")
    monkeypatch.setenv("LOGUI_RATE_LIMIT_RPS", "1000")
    monkeypatch.setenv("LOGUI_DB_ROOT", str(base_dir))

    from ai_proxy_ui.main import app

    client = TestClient(app)

    # Should still work with valid partition, skipping corrupted one
    r = client.get(
        "/ui/v1/requests",
        params={"since": str(d1), "to": str(d1 + dt.timedelta(days=1)), "limit": 10},
        headers={"Authorization": "Bearer user-key"},
    )
    assert r.status_code == 200
    data = r.json()
    assert len(data["items"]) == 2  # Only from valid partition


def test_requests_listing_no_partitions_found(tmp_path, monkeypatch):
    """Test requests listing when no partition files exist in date range."""
    base_dir = tmp_path / "logs" / "db"
    os.makedirs(base_dir, exist_ok=True)

    monkeypatch.setenv("LOGUI_API_KEYS", "user-key")
    monkeypatch.setenv("LOGUI_RATE_LIMIT_RPS", "1000")
    monkeypatch.setenv("LOGUI_DB_ROOT", str(base_dir))

    from ai_proxy_ui.main import app

    client = TestClient(app)

    # Request for a date range with no partitions
    r = client.get(
        "/ui/v1/requests",
        params={"since": "2025-01-01", "to": "2025-01-02", "limit": 10},
        headers={"Authorization": "Bearer user-key"},
    )
    assert r.status_code == 200
    data = r.json()
    assert data["items"] == []
    assert data["nextCursor"] is None


def test_requests_listing_empty_partitions(tmp_path, monkeypatch):
    """Test requests listing with empty partition files."""
    base_dir = tmp_path / "logs" / "db"
    d1 = dt.date(2025, 9, 9)

    # Create empty partition (0 rows)
    p1 = (
        base_dir
        / f"{d1.year:04d}"
        / f"{d1.month:02d}"
        / f"ai_proxy_{d1.strftime('%Y%m%d')}.sqlite3"
    )
    base_ts1 = int(dt.datetime(d1.year, d1.month, d1.day, 12, 0).timestamp())
    _make_partition(str(p1), rows=0, base_ts=base_ts1, start_id=0)

    monkeypatch.setenv("LOGUI_API_KEYS", "user-key")
    monkeypatch.setenv("LOGUI_RATE_LIMIT_RPS", "1000")
    monkeypatch.setenv("LOGUI_DB_ROOT", str(base_dir))

    from ai_proxy_ui.main import app

    client = TestClient(app)

    r = client.get(
        "/ui/v1/requests",
        params={"since": str(d1), "to": str(d1), "limit": 10},
        headers={"Authorization": "Bearer user-key"},
    )
    assert r.status_code == 200
    data = r.json()
    assert data["items"] == []
    assert data["nextCursor"] is None


def test_iter_partition_paths_function(tmp_path):
    """Test the _iter_partition_paths helper function directly."""
    from ai_proxy_ui.routers.requests import _iter_partition_paths

    base_dir = tmp_path / "logs" / "db"

    # Create some partition files
    d1 = dt.date(2025, 9, 1)
    d2 = dt.date(2025, 9, 2)
    d3 = dt.date(2025, 9, 3)

    for d in [d1, d2]:
        p = (
            base_dir
            / f"{d.year:04d}"
            / f"{d.month:02d}"
            / f"ai_proxy_{d.strftime('%Y%m%d')}.sqlite3"
        )
        os.makedirs(os.path.dirname(p), exist_ok=True)
        p.touch()

    # d3 partition doesn't exist

    # Test function
    paths = _iter_partition_paths(str(base_dir), d1, d3)

    # Should find only existing files
    assert len(paths) == 2
    for path in paths:
        assert os.path.isfile(path)
        assert "ai_proxy_" in os.path.basename(path)


def test_iter_range_with_merged_monthly_aggregates(tmp_path):
    """Test _iter_range_with_merged with monthly aggregate files."""
    from ai_proxy_ui.routers.requests import _iter_range_with_merged

    base_dir = tmp_path / "logs" / "db"

    # Create daily partitions for entire month
    year, month = 2025, 9
    daily_files = []
    for day in range(1, 31):  # September has 30 days
        d = dt.date(year, month, day)
        p = (
            base_dir
            / f"{d.year:04d}"
            / f"{d.month:02d}"
            / f"ai_proxy_{d.strftime('%Y%m%d')}.sqlite3"
        )
        os.makedirs(os.path.dirname(p), exist_ok=True)
        p.touch()
        daily_files.append(str(p))

    # Create a monthly aggregate file
    monthly_dir = base_dir / "monthly"
    monthly_file = monthly_dir / f"{year:04d}-{month:02d}.sqlite3"
    os.makedirs(monthly_dir, exist_ok=True)
    monthly_file.touch()

    # Test with query range that includes entire month but is wider
    # This should not use monthly aggregate because month is not fully inside range
    since = dt.date(year, month - 1, 15)  # Aug 15
    to = dt.date(year, month + 1, 15)  # Oct 15

    result = _iter_range_with_merged(str(base_dir), since, to)

    # Should use daily files, not monthly aggregate (month not fully inside range)
    # Just verify some daily files are included
    found_daily = any(daily_file in result for daily_file in daily_files)
    assert found_daily


def test_iter_range_with_merged_weekly_aggregates(tmp_path):
    """Test _iter_range_with_merged with weekly aggregate files."""
    from ai_proxy_ui.routers.requests import _iter_range_with_merged

    base_dir = tmp_path / "logs" / "db"

    # Create daily partitions for a full week
    # Week 36 of 2025 starts on Monday Sept 1st
    week_start = dt.date(2025, 9, 1)  # Monday
    daily_files = []
    for i in range(7):  # Full week
        d = week_start + dt.timedelta(days=i)
        p = (
            base_dir
            / f"{d.year:04d}"
            / f"{d.month:02d}"
            / f"ai_proxy_{d.strftime('%Y%m%d')}.sqlite3"
        )
        os.makedirs(os.path.dirname(p), exist_ok=True)
        p.touch()
        daily_files.append(str(p))

    # Create a weekly aggregate file
    weekly_dir = base_dir / "weekly"
    weekly_file = weekly_dir / "2025-W36.sqlite3"
    os.makedirs(weekly_dir, exist_ok=True)
    weekly_file.touch()

    # Test with query range that includes the week but is wider
    # This should not use weekly aggregate because week is not fully inside range
    since = week_start - dt.timedelta(days=2)  # Saturday before
    to = week_start + dt.timedelta(days=8)  # Tuesday after

    result = _iter_range_with_merged(str(base_dir), since, to)

    # Should use daily files, not weekly aggregate (week not fully inside range)
    # Just verify some daily files are included
    found_daily = any(daily_file in result for daily_file in daily_files)
    assert found_daily


def test_iter_range_with_merged_fallback_paths(tmp_path):
    """Test _iter_range_with_merged fallback when compute_*_path functions fail."""
    from ai_proxy_ui.routers.requests import _iter_range_with_merged
    import unittest.mock

    base_dir = tmp_path / "logs" / "db"

    # Create daily partitions
    d1 = dt.date(2025, 9, 1)
    p1 = (
        base_dir
        / f"{d1.year:04d}"
        / f"{d1.month:02d}"
        / f"ai_proxy_{d1.strftime('%Y%m%d')}.sqlite3"
    )
    os.makedirs(os.path.dirname(p1), exist_ok=True)
    p1.touch()

    # Create legacy monthly aggregate file
    monthly_dir = base_dir / "monthly"
    monthly_file = monthly_dir / "2025-09.sqlite3"
    os.makedirs(monthly_dir, exist_ok=True)
    monthly_file.touch()

    # Create legacy weekly aggregate file
    weekly_dir = base_dir / "weekly"
    weekly_file = weekly_dir / "2025-W36.sqlite3"
    os.makedirs(weekly_dir, exist_ok=True)
    weekly_file.touch()

    # Mock the compute functions to raise exceptions, forcing fallback
    with unittest.mock.patch(
        "ai_proxy.logdb.partitioning.compute_monthly_aggregate_path",
        side_effect=Exception("mock error"),
    ):
        with unittest.mock.patch(
            "ai_proxy.logdb.partitioning.compute_weekly_path",
            side_effect=Exception("mock error"),
        ):
            # Test monthly fallback
            since = dt.date(2025, 9, 1)
            to = dt.date(2025, 9, 30)
            result = _iter_range_with_merged(str(base_dir), since, to)

            # Should use legacy monthly path
            assert str(monthly_file) in result

            # Test weekly fallback
            since = dt.date(2025, 9, 1)  # Monday of week 36
            to = dt.date(2025, 9, 7)  # Sunday of week 36
            result = _iter_range_with_merged(str(base_dir), since, to)

            # Should use legacy weekly path
            assert str(weekly_file) in result


def test_iter_range_with_merged_mixed_scenarios(tmp_path):
    """Test _iter_range_with_merged with mixed daily/weekly/monthly files."""
    from ai_proxy_ui.routers.requests import _iter_range_with_merged

    base_dir = tmp_path / "logs" / "db"

    # Create some daily partitions
    daily_dates = [dt.date(2025, 9, 1), dt.date(2025, 9, 15), dt.date(2025, 9, 30)]
    daily_files = []
    for d in daily_dates:
        p = (
            base_dir
            / f"{d.year:04d}"
            / f"{d.month:02d}"
            / f"ai_proxy_{d.strftime('%Y%m%d')}.sqlite3"
        )
        os.makedirs(os.path.dirname(p), exist_ok=True)
        p.touch()
        daily_files.append(str(p))

    # Test partial month range - should use daily files
    since = dt.date(2025, 9, 1)
    to = dt.date(2025, 9, 15)

    result = _iter_range_with_merged(str(base_dir), since, to)

    # Should include daily files for partial ranges
    assert daily_files[0] in result  # Sept 1
    assert daily_files[1] in result  # Sept 15
    assert daily_files[2] not in result  # Sept 30 (outside range)
