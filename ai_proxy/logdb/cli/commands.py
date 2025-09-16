import datetime as _dt
import os
from typing import cast

from ..schema import open_connection_with_pragmas, run_integrity_check
from ..fts import build_fts_for_range, drop_fts_table
from ..bundle import create_bundle, verify_bundle, import_bundle
from ..transport import copy_with_resume
from ..merge import merge_partitions
from ..dialogs import (
    assign_dialogs_for_range,
    _parse_window_to_seconds,
    clear_dialogs_for_range,
)
from ..partitioning import ensure_partition_database


def cmd_init(args) -> int:
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


def _cmd_fts_build(args) -> int:
    since_date = (
        _dt.datetime.strptime(args.since, "%Y-%m-%d").date() if args.since else None
    )
    to_date = (
        _dt.datetime.strptime(args.to, "%Y-%m-%d").date()
        if args.to
        else _dt.date.today()
    )
    to_date = cast(_dt.date, to_date)

    flag_enabled = os.getenv("LOGDB_FTS_ENABLED", "false").lower() == "true"
    if not flag_enabled:
        print("FTS disabled by LOGDB_FTS_ENABLED")
        return 2

    results = build_fts_for_range(os.path.abspath(args.out), since_date, to_date)
    # Print concise report lines to stdout
    for db_path, rows_idx, rows_skip in results:
        print(f"{db_path} indexed={rows_idx} skipped={rows_skip}")
    return 0


def _cmd_fts_drop(args) -> int:
    since_date = (
        _dt.datetime.strptime(args.since, "%Y-%m-%d").date() if args.since else None
    )
    to_date = _dt.datetime.strptime(args.to, "%Y-%m-%d").date() if args.to else None
    base = os.path.abspath(args.out)
    if since_date is None and to_date is None:
        since_date = to_date = _dt.date.today()
    if since_date is None:
        since_date = to_date
    if to_date is None:
        to_date = since_date
    to_date = cast(_dt.date, to_date)
    cur = cast(_dt.date, since_date)  # since_date cannot be None at this point
    rc = 0
    while cur <= to_date:
        path = os.path.join(
            base,
            f"{cur.year:04d}",
            f"{cur.month:02d}",
            f"ai_proxy_{cur.strftime('%Y%m%d')}.sqlite3",
        )
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
        cur = cur + _dt.timedelta(days=1) if cur else _dt.date.today()
    return rc


def _cmd_bundle_create(args) -> int:
    since_date = _dt.datetime.strptime(args.since, "%Y-%m-%d").date()
    to_date = _dt.datetime.strptime(args.to, "%Y-%m-%d").date()
    # Env default for include_raw; CLI flag overrides when provided
    env_include_raw = os.getenv("LOGDB_BUNDLE_INCLUDE_RAW", "false").lower() == "true"
    include_raw = bool(args.include_raw) or env_include_raw
    # Resolve server_id: prefer env LOGDB_SERVER_ID, then .server_id under db dir, else empty
    server_id = os.getenv("LOGDB_SERVER_ID", "").strip()
    if not server_id:
        server_file = os.path.join(os.path.abspath(args.db), ".server_id")
        try:
            if os.path.isfile(server_file):
                with open(server_file, "r", encoding="utf-8") as f:
                    sid = f.read().strip()
                    if sid:
                        server_id = sid
        except Exception:
            server_id = ""
    # Create bundle
    create_bundle(
        base_db_dir=os.path.abspath(args.db),
        since=since_date,
        to=to_date,
        out_path=os.path.abspath(args.out),
        include_raw=include_raw,
        raw_logs_dir=os.path.abspath(args.raw) if include_raw else None,
        server_id=server_id,
    )
    print(args.out)
    return 0


def _cmd_bundle_verify(args) -> int:
    ok = verify_bundle(os.path.abspath(args.bundle))
    print("ok" if ok else "fail")
    return 0 if ok else 1


def _cmd_bundle_transfer(args) -> int:
    # Perform resumable copy, then verify destination checksum equals source
    size, sha = copy_with_resume(os.path.abspath(args.src), os.path.abspath(args.dest))
    # If file appears to be a bundle, optionally run verify to ensure integrity of contents
    try:
        if str(args.dest).endswith(".tgz"):
            ok = verify_bundle(os.path.abspath(args.dest))
            print(f"bytes={size} sha256={sha} verify={'ok' if ok else 'fail'}")
            return 0 if ok else 1
    except Exception:
        # If verification fails due to non-bundle, still consider copy success
        pass
    print(f"bytes={size} sha256={sha}")
    return 0


def _cmd_dialogs_assign(args) -> int:
    if os.getenv("LOGDB_GROUPING_ENABLED", "false").lower() != "true":
        print("Dialogs disabled by LOGDB_GROUPING_ENABLED")
        return 2
    since_date = (
        _dt.datetime.strptime(args.since, "%Y-%m-%d").date() if args.since else None
    )
    to_date = _dt.datetime.strptime(args.to, "%Y-%m-%d").date() if args.to else None
    window_seconds = _parse_window_to_seconds(args.window)
    results = assign_dialogs_for_range(
        os.path.abspath(args.out), since_date, to_date, window_seconds
    )
    for db_path, updated in results:
        print(f"{db_path} updated={updated}")
    return 0


def _cmd_dialogs_clear(args) -> int:
    if os.getenv("LOGDB_GROUPING_ENABLED", "false").lower() != "true":
        print("Dialogs disabled by LOGDB_GROUPING_ENABLED")
        return 2
    since_date = (
        _dt.datetime.strptime(args.since, "%Y-%m-%d").date() if args.since else None
    )
    to_date = _dt.datetime.strptime(args.to, "%Y-%m-%d").date() if args.to else None
    results = clear_dialogs_for_range(os.path.abspath(args.out), since_date, to_date)
    for db_path, updated in results:
        print(f"{db_path} cleared={updated}")
    return 0


def _cmd_bundle_import(args) -> int:
    imp, skip = import_bundle(os.path.abspath(args.bundle), os.path.abspath(args.dest))
    print(f"imported={imp} skipped={skip}")
    return 0


def _cmd_merge(args) -> int:
    nsrc, total, status = merge_partitions(
        os.path.abspath(args.src), os.path.abspath(args.dst)
    )
    print(f"sources={nsrc} total_requests={total} integrity={status}")
    return 0 if status == "ok" else 1
