import argparse
import datetime as _dt
import os
from typing import Optional

from .partitioning import ensure_partition_database
from .ingest import add_cli as add_ingest_cli
from .schema import open_connection_with_pragmas, run_integrity_check


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

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())



