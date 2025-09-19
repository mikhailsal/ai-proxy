import datetime as _dt
import os
from typing import cast

from ..schema import open_connection_with_pragmas, run_integrity_check
from ..fts import build_fts_for_range, drop_fts_table
from ..bundle import create_bundle, verify_bundle, import_bundle
from ..transport import copy_with_resume
from ..merge import merge_partitions, merge_partitions_from_files
from ..dialogs import (
    assign_dialogs_for_range,
    _parse_window_to_seconds,
    clear_dialogs_for_range,
)
from ..partitioning import (
    ensure_partition_database,
    compute_partition_path,
    compute_weekly_path,
    compute_monthly_aggregate_path,
)


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


def _discover_daily_partitions(base_dir: str, since: _dt.date, to: _dt.date):
    cur = since
    paths = []
    while cur <= to:
        paths.append(compute_partition_path(base_dir, cur))
        cur = cur + _dt.timedelta(days=1)
    return [p for p in paths if os.path.isfile(p)]


def _discover_weekly_targets(base_dir: str, since: _dt.date, to: _dt.date):
    cur = since
    targets: dict[str, str] = {}
    while cur <= to:
        tgt = compute_weekly_path(base_dir, cur)
        key = os.path.dirname(tgt)
        targets.setdefault(key, tgt)
        cur = cur + _dt.timedelta(days=1)
    return list(targets.values())


def _discover_monthly_targets(base_dir: str, since: _dt.date, to: _dt.date):
    cur = since
    targets: dict[str, str] = {}
    while cur <= to:
        tgt = compute_monthly_aggregate_path(base_dir, cur)
        key = os.path.dirname(tgt)
        targets.setdefault(key, tgt)
        cur = cur + _dt.timedelta(days=1)
    return list(targets.values())


def cmd_auto(args) -> int:
    """Default operation: ingest recent logs into DB, then compact partitions.

    Behavior:
    - Source logs default: ./logs
    - DB base dir default: ./logs/db
    - Date range default: from earliest day seen in raw logs up to today.
      Practically, we scan all .log files and let checkpoints skip already ingested bytes.
    - After ingestion, if today is not the last day of its ISO week, no weekly
      compaction is performed for the open week. Completed weeks are merged into
      a weekly DB. Similarly for completed months, merge daily or weekly into
      a monthly DB.
    """
    # Gate by feature flag like ingest
    if os.getenv("LOGDB_ENABLED", "false").lower() != "true":
        print("Auto disabled by LOGDB_ENABLED")
        return 2

    source = os.path.abspath(getattr(args, "source", "logs"))
    base = os.path.abspath(getattr(args, "out", "logs/db"))

    # Stage 1: ingest all log files; checkpoints guarantee idempotence
    from ..ingest import ingest_logs as _ingest

    stats = _ingest(source, base, None, None)
    print(
        f"auto: ingested files={stats.files_ingested} rows={stats.rows_inserted} skipped={stats.rows_skipped}"
    )

    # Stage 2: compaction
    today = _dt.date.today()

    # Determine earliest and latest partitions present
    # We'll scan under base for daily-shaped files YYYY/MM/ai_proxy_YYYYMMDD.sqlite3
    daily_files = []
    for root, _dirs, names in os.walk(base):
        for n in names:
            if n.startswith("ai_proxy_") and n.endswith(".sqlite3"):
                # Heuristic: skip weekly (YYYYWNN) and monthly (YYYYMM) aggregates by directory name
                # Daily live under YYYY/MM, weekly under YYYY/WNN, monthly under YYYY/MNN
                parts = os.path.normpath(root).split(os.sep)
                if len(parts) >= 2 and parts[-2].isdigit() and parts[-1].isdigit():
                    daily_files.append(os.path.join(root, n))

    # Group daily files per ISO week and per month
    from collections import defaultdict

    week_to_files = defaultdict(list)
    month_to_files = defaultdict(list)
    for p in daily_files:
        # parse date from filename ai_proxy_YYYYMMDD.sqlite3
        try:
            base_name = os.path.basename(p)
            date_str = base_name.replace("ai_proxy_", "").replace(".sqlite3", "")
            y = int(date_str[0:4])
            m = int(date_str[4:6])
            d = int(date_str[6:8])
            dte = _dt.date(y, m, d)
        except Exception:
            continue
        iso_year, iso_week, iso_weekday = dte.isocalendar()
        week_key = (iso_year, iso_week)
        week_to_files[week_key].append(p)
        month_key = (dte.year, dte.month)
        month_to_files[month_key].append(p)

    # Merge completed ISO weeks into weekly targets
    for (wy, ww), files in sorted(week_to_files.items()):
        # Completed week when the last day is past Sunday (ISO weekday 7)
        # If current week equals (wy, ww), skip to keep it live
        t_y, t_w, _ = today.isocalendar()
        if (wy, ww) == (t_y, t_w):
            continue
        target = compute_weekly_path(base, _dt.date.fromisocalendar(wy, ww, 1))
        os.makedirs(os.path.dirname(target), exist_ok=True)
        nsrc, total, status = merge_partitions_from_files(files, target)
        print(
            f"auto: weekly_merge {target} sources={nsrc} total={total} status={status}"
        )
        # Optional cleanup of daily sources after successful merge
        if (
            status == "ok"
            and os.getenv("LOGDB_CLEANUP_AFTER_MERGE", "false").lower() == "true"
        ):
            for f in files:
                try:
                    os.remove(f)
                except Exception:
                    pass

    # Merge completed months into monthly targets from daily files
    cm_y, cm_m = today.year, today.month
    for (yy, mm), files in sorted(month_to_files.items()):
        if (yy, mm) == (cm_y, cm_m):
            continue
        target = compute_monthly_aggregate_path(base, _dt.date(yy, mm, 1))
        os.makedirs(os.path.dirname(target), exist_ok=True)
        nsrc, total, status = merge_partitions_from_files(files, target)
        print(
            f"auto: monthly_merge {target} sources={nsrc} total={total} status={status}"
        )
        # Optional cleanup of daily sources after successful merge
        if (
            status == "ok"
            and os.getenv("LOGDB_CLEANUP_AFTER_MERGE", "false").lower() == "true"
        ):
            for f in files:
                try:
                    os.remove(f)
                except Exception:
                    pass

    # Optionally build FTS for the ingested range when enabled
    if os.getenv("LOGDB_FTS_ENABLED", "false").lower() == "true":
        res = build_fts_for_range(base, None, today)
        for db_path, rows_idx, rows_skip in res:
            print(f"auto: fts {db_path} indexed={rows_idx} skipped={rows_skip}")

    return 0
