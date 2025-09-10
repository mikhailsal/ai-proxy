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
    year_dir = os.path.join(base_dir, f"{date.year:04d}")
    month_dir = os.path.join(year_dir, f"{date.month:02d}")
    filename = f"ai_proxy_{date.strftime('%Y%m%d')}.sqlite3"
    return os.path.join(month_dir, filename)


def ensure_partition_database(base_dir: str, date: _dt.date) -> str:
    db_path = compute_partition_path(base_dir, date)
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    ensure_schema(db_path)
    return db_path



