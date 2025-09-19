import datetime as _dt
import os
from dataclasses import dataclass

from .schema import ensure_schema


@dataclass(frozen=True)
class Partition:
    year: int
    month: int
    day: int


def compute_partition_path(base_dir: str, date: _dt.date) -> str:
    """Compute partition path based on granularity.

    Granularity is controlled by env LOGDB_PARTITION_GRANULARITY with values:
    - "daily" (default): logs/db/YYYY/MM/ai_proxy_YYYYMMDD.sqlite3
    - "weekly": logs/db/YYYY/WNN/ai_proxy_YYYYWNN.sqlite3 (ISO week)
    """
    granularity = os.getenv("LOGDB_PARTITION_GRANULARITY", "daily").strip().lower()
    year_dir = os.path.join(base_dir, f"{date.year:04d}")
    if granularity == "weekly":
        iso_year, iso_week, _ = date.isocalendar()
        year_dir = os.path.join(base_dir, f"{iso_year:04d}")
        week_dir = os.path.join(year_dir, f"W{iso_week:02d}")
        filename = f"ai_proxy_{iso_year:04d}W{iso_week:02d}.sqlite3"
        return os.path.join(week_dir, filename)

    # Default: daily
    month_dir = os.path.join(year_dir, f"{date.month:02d}")
    filename = f"ai_proxy_{date.strftime('%Y%m%d')}.sqlite3"
    return os.path.join(month_dir, filename)


def ensure_partition_database(base_dir: str, date: _dt.date) -> str:
    db_path = compute_partition_path(base_dir, date)
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    ensure_schema(db_path)
    return db_path


def control_database_path(base_dir: str) -> str:
    """Return the path to the control database used for checkpoints/server rows."""
    return os.path.join(os.path.abspath(base_dir), "control.sqlite3")


def ensure_control_database(base_dir: str) -> str:
    path = control_database_path(base_dir)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    ensure_schema(path)
    return path


def compute_weekly_path(base_dir: str, date: _dt.date) -> str:
    """Return the weekly aggregate path for the ISO week containing date.

    Path shape: base/YYYY/WNN/ai_proxy_YYYYWNN.sqlite3
    """
    iso_year, iso_week, _ = date.isocalendar()
    year_dir = os.path.join(base_dir, f"{iso_year:04d}")
    week_dir = os.path.join(year_dir, f"W{iso_week:02d}")
    filename = f"ai_proxy_{iso_year:04d}W{iso_week:02d}.sqlite3"
    return os.path.join(week_dir, filename)


def compute_monthly_aggregate_path(base_dir: str, date: _dt.date) -> str:
    """Return the monthly aggregate path for the month containing date.

    Path shape: base/YYYY/MNN/ai_proxy_YYYYMM.sqlite3 (MNN distinguishes from daily 'MM')
    """
    year_dir = os.path.join(base_dir, f"{date.year:04d}")
    month_dir = os.path.join(year_dir, f"M{date.month:02d}")
    filename = f"ai_proxy_{date.year:04d}{date.month:02d}.sqlite3"
    return os.path.join(month_dir, filename)
