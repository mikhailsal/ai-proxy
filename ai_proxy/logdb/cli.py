import argparse
import datetime as _dt
import os
from typing import Optional

from .partitioning import ensure_partition_database
from .ingest import add_cli as add_ingest_cli
from .schema import open_connection_with_pragmas, run_integrity_check
from .fts import build_fts_for_range, drop_fts_table
from .bundle import create_bundle, verify_bundle
from .dialogs import assign_dialogs_for_range, _parse_window_to_seconds, clear_dialogs_for_range


def cmd_init(args: argparse.Namespace) -> int:
    if args.date:
        target_date = _dt.datetime.strptime(args.date, "%Y-%m-%d").date()
    else:
        target_date = _dt.date.today()

    base_dir = os.path.abspath(args.out or "logs/db")
    db_path = ensure_partition_database(base_dir, target_date)

    conn = open_connection_with_pragmas(db_path)
    try:
        status = run_integrity_check(conn)
    finally:
        conn.close()

    print(db_path)
    print(status)
    return 0 if status == "ok" else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="logdb", description="Log DB utilities")
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="Initialize schema for a partition date")
    p_init.add_argument("--date", help="Partition date YYYY-MM-DD", required=False)
    p_init.add_argument("--out", help="Base directory for DB partitions", required=False, default="logs/db")
    p_init.set_defaults(func=cmd_init)

    # Ingest subcommand
    add_ingest_cli(sub)

    # FTS subcommands
    p_fts = sub.add_parser("fts", help="FTS index utilities")
    sub_fts = p_fts.add_subparsers(dest="fts_command", required=True)

    p_fts_build = sub_fts.add_parser("build", help="Build FTS5 index for a date range")
    p_fts_build.add_argument("--out", help="Base directory for DB partitions", required=False, default="logs/db")
    p_fts_build.add_argument("--since", help="Start date YYYY-MM-DD", required=False)
    p_fts_build.add_argument("--to", help="End date YYYY-MM-DD", required=False)

    def _cmd_fts_build(args: argparse.Namespace) -> int:
        since_date = _dt.datetime.strptime(args.since, "%Y-%m-%d").date() if args.since else None
        to_date = _dt.datetime.strptime(args.to, "%Y-%m-%d").date() if args.to else None

        flag_enabled = (os.getenv("LOGDB_FTS_ENABLED", "false").lower() == "true")
        if not flag_enabled:
            print("FTS disabled by LOGDB_FTS_ENABLED")
            return 2

        results = build_fts_for_range(os.path.abspath(args.out), since_date, to_date)
        # Print concise report lines to stdout
        for db_path, rows_idx, rows_skip in results:
            print(f"{db_path} indexed={rows_idx} skipped={rows_skip}")
        return 0

    p_fts_build.set_defaults(func=_cmd_fts_build)

    p_fts_drop = sub_fts.add_parser("drop", help="Drop FTS5 index table for a date range (non-destructive to base tables)")
    p_fts_drop.add_argument("--out", help="Base directory for DB partitions", required=False, default="logs/db")
    p_fts_drop.add_argument("--since", help="Start date YYYY-MM-DD", required=False)
    p_fts_drop.add_argument("--to", help="End date YYYY-MM-DD", required=False)

    def _cmd_fts_drop(args: argparse.Namespace) -> int:
        since_date = _dt.datetime.strptime(args.since, "%Y-%m-%d").date() if args.since else None
        to_date = _dt.datetime.strptime(args.to, "%Y-%m-%d").date() if args.to else None
        base = os.path.abspath(args.out)
        if since_date is None and to_date is None:
            since_date = to_date = _dt.date.today()
        if since_date is None:
            since_date = to_date
        if to_date is None:
            to_date = since_date
        cur = since_date
        rc = 0
        while cur <= to_date:
            path = os.path.join(base, f"{cur.year:04d}", f"{cur.month:02d}", f"ai_proxy_{cur.strftime('%Y%m%d')}.sqlite3")
            if os.path.isfile(path):
                try:
                    conn = open_connection_with_pragmas(path)
                    try:
                        drop_fts_table(conn)
                    finally:
                        conn.close()
                    print(f"{path} fts dropped")
                except Exception as e:
                    print(f"{path} drop_error={e}")
                    rc = 1
            cur = cur + _dt.timedelta(days=1)
        return rc

    p_fts_drop.set_defaults(func=_cmd_fts_drop)

    # Bundle subcommands
    p_bundle = sub.add_parser("bundle", help="Bundle operations")
    sub_bundle = p_bundle.add_subparsers(dest="bundle_command", required=True)

    p_bundle_create = sub_bundle.add_parser("create", help="Create a log bundle tar.gz")
    p_bundle_create.add_argument("--since", required=True, help="Start date YYYY-MM-DD")
    p_bundle_create.add_argument("--to", required=True, help="End date YYYY-MM-DD")
    p_bundle_create.add_argument("--out", required=True, help="Output bundle file path (.tgz)")
    p_bundle_create.add_argument("--db", required=False, default="logs/db", help="Base directory for DB partitions")
    p_bundle_create.add_argument("--include-raw", action="store_true", help="Include raw .log files in bundle")
    p_bundle_create.add_argument("--raw", required=False, default="logs", help="Source logs directory for raw files")

    def _cmd_bundle_create(args: argparse.Namespace) -> int:
        since_date = _dt.datetime.strptime(args.since, "%Y-%m-%d").date()
        to_date = _dt.datetime.strptime(args.to, "%Y-%m-%d").date()
        include_raw = bool(args.include_raw)
        # Create bundle
        create_bundle(
            base_db_dir=os.path.abspath(args.db),
            since=since_date,
            to=to_date,
            out_path=os.path.abspath(args.out),
            include_raw=include_raw,
            raw_logs_dir=os.path.abspath(args.raw) if include_raw else None,
        )
        print(args.out)
        return 0

    p_bundle_create.set_defaults(func=_cmd_bundle_create)

    p_bundle_verify = sub_bundle.add_parser("verify", help="Verify a log bundle")
    p_bundle_verify.add_argument("bundle", help="Path to bundle .tgz")

    def _cmd_bundle_verify(args: argparse.Namespace) -> int:
        ok = verify_bundle(os.path.abspath(args.bundle))
        print("ok" if ok else "fail")
        return 0 if ok else 1

    p_bundle_verify.set_defaults(func=_cmd_bundle_verify)

    # Dialog grouping subcommands
    p_dialogs = sub.add_parser("dialogs", help="Dialog grouping utilities")
    sub_dialogs = p_dialogs.add_subparsers(dest="dialogs_command", required=True)

    p_dialogs_assign = sub_dialogs.add_parser("assign", help="Assign dialog_id for a date range")
    p_dialogs_assign.add_argument("--out", required=False, default="logs/db", help="Base directory for DB partitions")
    p_dialogs_assign.add_argument("--since", required=False, help="Start date YYYY-MM-DD")
    p_dialogs_assign.add_argument("--to", required=False, help="End date YYYY-MM-DD")
    p_dialogs_assign.add_argument(
        "--window",
        required=False,
        default="30m",
        help="Window size (e.g., 30m, 15m, 2h, 1800s)",
    )

    def _cmd_dialogs_assign(args: argparse.Namespace) -> int:
        if os.getenv("LOGDB_GROUPING_ENABLED", "false").lower() != "true":
            print("Dialogs disabled by LOGDB_GROUPING_ENABLED")
            return 2
        since_date = _dt.datetime.strptime(args.since, "%Y-%m-%d").date() if args.since else None
        to_date = _dt.datetime.strptime(args.to, "%Y-%m-%d").date() if args.to else None
        window_seconds = _parse_window_to_seconds(args.window)
        results = assign_dialogs_for_range(os.path.abspath(args.out), since_date, to_date, window_seconds)
        for db_path, updated in results:
            print(f"{db_path} updated={updated}")
        return 0

    p_dialogs_assign.set_defaults(func=_cmd_dialogs_assign)

    p_dialogs_clear = sub_dialogs.add_parser("clear", help="Clear dialog_id values for a date range")
    p_dialogs_clear.add_argument("--out", required=False, default="logs/db", help="Base directory for DB partitions")
    p_dialogs_clear.add_argument("--since", required=False, help="Start date YYYY-MM-DD")
    p_dialogs_clear.add_argument("--to", required=False, help="End date YYYY-MM-DD")

    def _cmd_dialogs_clear(args: argparse.Namespace) -> int:
        if os.getenv("LOGDB_GROUPING_ENABLED", "false").lower() != "true":
            print("Dialogs disabled by LOGDB_GROUPING_ENABLED")
            return 2
        since_date = _dt.datetime.strptime(args.since, "%Y-%m-%d").date() if args.since else None
        to_date = _dt.datetime.strptime(args.to, "%Y-%m-%d").date() if args.to else None
        results = clear_dialogs_for_range(os.path.abspath(args.out), since_date, to_date)
        for db_path, updated in results:
            print(f"{db_path} cleared={updated}")
        return 0

    p_dialogs_clear.set_defaults(func=_cmd_dialogs_clear)

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())



