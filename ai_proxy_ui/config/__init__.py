"""
Configuration helpers for the Logs UI API.
"""
import os
from typing import Set


def _get_allowed_origins() -> list[str]:
    origins = os.getenv("LOGUI_ALLOWED_ORIGINS", "*")
    # CSV to list, trim whitespace
    parts = [p.strip() for p in origins.split(",") if p.strip()]
    return parts if parts else ["*"]


def _get_bool_env(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _get_csv_env(name: str) -> set[str]:
    raw = os.getenv(name, "")
    return {item.strip() for item in raw.split(",") if item.strip()}


API_VERSION = "ui.v1"
ENVIRONMENT = os.getenv("ENVIRONMENT", "development").strip().lower()
