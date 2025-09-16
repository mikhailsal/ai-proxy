import argparse

from ..ingest import add_cli as add_ingest_cli

from .commands import (
    cmd_init,
    _cmd_fts_build,
    _cmd_fts_drop,
    _cmd_bundle_create,
    _cmd_bundle_verify,
    _cmd_bundle_transfer,
    _cmd_dialogs_assign,
    _cmd_dialogs_clear,
    _cmd_bundle_import,
    _cmd_merge,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="logdb", description="Log DB utilities")
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="Initialize schema for a partition date")
    p_init.add_argument("--date", help="Partition date YYYY-MM-DD", required=False)
    p_init.add_argument(
        "--out",
        help="Base directory for DB partitions",
        required=False,
        default="logs/db",
    )
    p_init.set_defaults(func=cmd_init)

    # Ingest subcommand
    add_ingest_cli(sub)

    # FTS subcommands
    p_fts = sub.add_parser("fts", help="FTS index utilities")
    sub_fts = p_fts.add_subparsers(dest="fts_command", required=True)

    p_fts_build = sub_fts.add_parser("build", help="Build FTS5 index for a date range")
    p_fts_build.add_argument(
        "--out",
        help="Base directory for DB partitions",
        required=False,
        default="logs/db",
    )
    p_fts_build.add_argument("--since", help="Start date YYYY-MM-DD", required=False)
    p_fts_build.add_argument("--to", help="End date YYYY-MM-DD", required=False)
    p_fts_build.set_defaults(func=_cmd_fts_build)

    p_fts_drop = sub_fts.add_parser(
        "drop",
        help="Drop FTS5 index table for a date range (non-destructive to base tables)",
    )
    p_fts_drop.add_argument(
        "--out",
        help="Base directory for DB partitions",
        required=False,
        default="logs/db",
    )
    p_fts_drop.add_argument("--since", help="Start date YYYY-MM-DD", required=False)
    p_fts_drop.add_argument("--to", help="End date YYYY-MM-DD", required=False)
    p_fts_drop.set_defaults(func=_cmd_fts_drop)

    # Bundle subcommands
    p_bundle = sub.add_parser("bundle", help="Bundle operations")
    sub_bundle = p_bundle.add_subparsers(dest="bundle_command", required=True)

    p_bundle_create = sub_bundle.add_parser("create", help="Create a log bundle tar.gz")
    p_bundle_create.add_argument("--since", required=True, help="Start date YYYY-MM-DD")
    p_bundle_create.add_argument("--to", required=True, help="End date YYYY-MM-DD")
    p_bundle_create.add_argument(
        "--out", required=True, help="Output bundle file path (.tgz)"
    )
    p_bundle_create.add_argument(
        "--db",
        required=False,
        default="logs/db",
        help="Base directory for DB partitions",
    )
    p_bundle_create.add_argument(
        "--include-raw",
        action="store_true",
        help="Include raw .log files in bundle (overrides env)",
    )
    p_bundle_create.add_argument(
        "--raw",
        required=False,
        default="logs",
        help="Source logs directory for raw files",
    )
    p_bundle_create.set_defaults(func=_cmd_bundle_create)

    p_bundle_verify = sub_bundle.add_parser("verify", help="Verify a log bundle")
    p_bundle_verify.add_argument("bundle", help="Path to bundle .tgz")
    p_bundle_verify.set_defaults(func=_cmd_bundle_verify)

    p_bundle_transfer = sub_bundle.add_parser(
        "transfer", help="Transfer a bundle file with resume to destination path"
    )
    p_bundle_transfer.add_argument("src", help="Source bundle path (.tgz)")
    p_bundle_transfer.add_argument("dest", help="Destination path")
    p_bundle_transfer.set_defaults(func=_cmd_bundle_transfer)

    # Dialog grouping subcommands
    p_dialogs = sub.add_parser("dialogs", help="Dialog grouping utilities")
    sub_dialogs = p_dialogs.add_subparsers(dest="dialogs_command", required=True)

    p_dialogs_assign = sub_dialogs.add_parser(
        "assign", help="Assign dialog_id for a date range"
    )
    p_dialogs_assign.add_argument(
        "--out",
        required=False,
        default="logs/db",
        help="Base directory for DB partitions",
    )
    p_dialogs_assign.add_argument(
        "--since", required=False, help="Start date YYYY-MM-DD"
    )
    p_dialogs_assign.add_argument("--to", required=False, help="End date YYYY-MM-DD")
    p_dialogs_assign.add_argument(
        "--window",
        required=False,
        default="30m",
        help="Window size (e.g., 30m, 15m, 2h, 1800s)",
    )
    p_dialogs_assign.set_defaults(func=_cmd_dialogs_assign)

    p_dialogs_clear = sub_dialogs.add_parser(
        "clear", help="Clear dialog_id values for a date range"
    )
    p_dialogs_clear.add_argument(
        "--out",
        required=False,
        default="logs/db",
        help="Base directory for DB partitions",
    )
    p_dialogs_clear.add_argument(
        "--since", required=False, help="Start date YYYY-MM-DD"
    )
    p_dialogs_clear.add_argument("--to", required=False, help="End date YYYY-MM-DD")
    p_dialogs_clear.set_defaults(func=_cmd_dialogs_clear)

    # Bundle import subcommand
    p_bundle_import = sub_bundle.add_parser(
        "import", help="Import a log bundle into destination dir"
    )
    p_bundle_import.add_argument("bundle", help="Path to bundle .tgz")
    p_bundle_import.add_argument(
        "--dest",
        required=False,
        default="logs/db",
        help="Destination base directory for DB partitions",
    )
    p_bundle_import.set_defaults(func=_cmd_bundle_import)

    # Merge utility
    p_merge = sub.add_parser(
        "merge", help="Merge partitions from a directory into a single SQLite file"
    )
    p_merge.add_argument(
        "--from",
        dest="src",
        required=True,
        help="Source directory containing partitions",
    )
    p_merge.add_argument(
        "--to", dest="dst", required=True, help="Destination SQLite file path"
    )
    p_merge.set_defaults(func=_cmd_merge)

    return parser
