"""Log database utilities: schema creation and partitioning.

This module provides programmatic APIs used by the `logdb` CLI and by tests
to initialize SQLite databases for structured log storage.
"""

from .schema import (
    create_or_migrate_schema,
    open_connection_with_pragmas,
    run_integrity_check,
)
from .partitioning import (
    compute_partition_path,
    ensure_partition_database,
)

__all__ = [
    "create_or_migrate_schema",
    "open_connection_with_pragmas",
    "run_integrity_check",
    "compute_partition_path",
    "ensure_partition_database",
]



