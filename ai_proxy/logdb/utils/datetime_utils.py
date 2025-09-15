import datetime as dt
from typing import Optional


def safe_iso_to_datetime(ts: str) -> Optional[dt.datetime]:
    if not ts:
        return None
    try:
        # Accept timestamps like 2025-06-26T08:42:42.753538Z
        if ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        return dt.datetime.fromisoformat(ts)
    except Exception:
        return None