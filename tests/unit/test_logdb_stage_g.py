import datetime as dt
import os
import sqlite3

from ai_proxy.logdb.bundle import create_bundle, import_bundle
from ai_proxy.logdb.partitioning import compute_partition_path
from ai_proxy.logdb.merge import merge_partitions


def _make_partition(base_dir: str, date: dt.date, rows: int, start_id: int = 0) -> str:
    db_path = compute_partition_path(base_dir, date)
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(
            """
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS servers (
              server_id TEXT PRIMARY KEY,
              hostname TEXT,
              env TEXT,
              first_seen_ts INTEGER
            );
            CREATE TABLE IF NOT EXISTS requests (
              request_id TEXT PRIMARY KEY,
              server_id TEXT NOT NULL,
              ts INTEGER NOT NULL,
              endpoint TEXT NOT NULL,
              model_original TEXT,
              model_mapped TEXT,
              status_code INTEGER,
              latency_ms REAL,
              api_key_hash TEXT,
              request_json TEXT NOT NULL,
              response_json TEXT NOT NULL,
              dialog_id TEXT
            );
            CREATE TABLE IF NOT EXISTS ingest_sources (
              source_path TEXT PRIMARY KEY,
              sha256 TEXT,
              bytes_ingested INTEGER,
              mtime INTEGER,
              last_scan_ts INTEGER
            );
            """
        )
        # Insert rows
        with conn:
            conn.execute(
                "INSERT OR IGNORE INTO servers(server_id, hostname, env, first_seen_ts) VALUES(?,?,?,?)",
                ("srv-1", "localhost", "test", int(dt.datetime.now().timestamp())),
            )
            for i in range(rows):
                rid = f"r{start_id + i:04d}"
                conn.execute(
                    "INSERT OR IGNORE INTO requests(request_id, server_id, ts, endpoint, model_original, model_mapped, status_code, latency_ms, api_key_hash, request_json, response_json, dialog_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,NULL)",
                    (
                        rid,
                        "srv-1",
                        int(dt.datetime.combine(date, dt.time(12, 0)).timestamp()) + i,
                        "/v1/chat/completions",
                        "m",
                        "m",
                        200,
                        10.0,
                        "k",
                        "{}",
                        "{}",
                    ),
                )
    finally:
        conn.close()
    return db_path


def test_bundle_import_idempotent_and_attach_query(tmp_path):
    base_db = tmp_path / "src" / "logs" / "db"
    date1 = dt.date(2025, 9, 9)
    date2 = dt.date(2025, 9, 10)
    _make_partition(str(base_db), date1, 3, 0)
    _make_partition(str(base_db), date2, 2, 100)

    bundle_path = tmp_path / "bundles" / "b.tgz"
    os.makedirs(bundle_path.parent, exist_ok=True)
    create_bundle(str(base_db), date1, date2, str(bundle_path), include_raw=False)

    dest_dir = tmp_path / "dest" / "db"
    imp1 = import_bundle(str(bundle_path), str(dest_dir))
    imp2 = import_bundle(str(bundle_path), str(dest_dir))
    assert imp1[0] >= 1 and imp2[0] == 0  # second run should skip all

    # Attach and do a simple cross-partition query by opening both files
    db_files = []
    for root, _dirs, names in os.walk(dest_dir):
        for n in names:
            if n.endswith(".sqlite3"):
                db_files.append(os.path.join(root, n))
    assert len(db_files) == 2
    # Validate each has rows
    for p in db_files:
        conn = sqlite3.connect(p)
        try:
            cur = conn.execute("SELECT COUNT(*) FROM requests")
            assert int(cur.fetchone()[0]) >= 1
        finally:
            conn.close()


def test_merge_produces_equal_counts_and_ok(tmp_path):
    src_dir = tmp_path / "srcdb"
    date1 = dt.date(2025, 9, 9)
    date2 = dt.date(2025, 9, 10)
    _make_partition(str(src_dir), date1, 4, 0)
    _make_partition(str(src_dir), date2, 6, 100)

    dest = tmp_path / "monthly.sqlite3"
    nsrc, total, status = merge_partitions(str(src_dir), str(dest))
    assert nsrc == 2
    assert total == 10
    assert status == "ok"

    # Re-run merge should be idempotent and keep counts same
    nsrc2, total2, status2 = merge_partitions(str(src_dir), str(dest))
    assert nsrc2 == 2
    assert total2 == 10
    assert status2 == "ok"


def test_import_bundle_raises_on_checksum_mismatch(tmp_path):
    # Prepare two partitions and build a bundle
    base_db = tmp_path / "src" / "logs" / "db"
    d1 = dt.date(2025, 9, 18)
    d2 = dt.date(2025, 9, 19)
    _make_partition(str(base_db), d1, 1, 0)
    _make_partition(str(base_db), d2, 1, 10)

    bundle_path = tmp_path / "bundles" / "b-bad.tgz"
    os.makedirs(bundle_path.parent, exist_ok=True)
    create_bundle(str(base_db), d1, d2, str(bundle_path), include_raw=False)

    # Tamper one DB entry inside the tar to break checksum
    work = tmp_path / "wrk"
    os.makedirs(work, exist_ok=True)
    import tarfile
    with tarfile.open(bundle_path, "r:gz") as tar:
        tar.extractall(work)
    # Find a db file and modify
    target = None
    for root, _dirs, names in os.walk(work / "db"):
        for n in names:
            if n.endswith(".sqlite3"):
                target = os.path.join(root, n)
                break
        if target:
            break
    assert target is not None
    with open(target, "ab") as f:
        f.write(b"X")
    # Repack without updating metadata.json
    bad = tmp_path / "bundles" / "b-bad2.tgz"
    with tarfile.open(bad, "w:gz") as tar:
        tar.add(work / "db", arcname="db")
        tar.add(work / "metadata.json", arcname="metadata.json")

    dest_dir = tmp_path / "dest" / "db"
    from pytest import raises
    with raises(ValueError):
        import_bundle(str(bad), str(dest_dir))


def test_cross_db_attach_query_single_connection(tmp_path):
    # Create two partitions and import via bundle
    base_db = tmp_path / "src" / "logs" / "db"
    d1 = dt.date(2025, 9, 20)
    d2 = dt.date(2025, 9, 21)
    _make_partition(str(base_db), d1, 2, 0)
    _make_partition(str(base_db), d2, 3, 100)

    bundle_path = tmp_path / "bundles" / "b2.tgz"
    os.makedirs(bundle_path.parent, exist_ok=True)
    create_bundle(str(base_db), d1, d2, str(bundle_path), include_raw=False)

    dest_dir = tmp_path / "dest2" / "db"
    import_bundle(str(bundle_path), str(dest_dir))

    # Collect two db files
    db_files = []
    for root, _dirs, names in os.walk(dest_dir):
        for n in names:
            if n.endswith(".sqlite3"):
                db_files.append(os.path.join(root, n))
    assert len(db_files) == 2

    # Open single connection, attach both, run a cross-DB aggregate
    # Use an in-memory main DB just to run the query
    conn = sqlite3.connect(":memory:")
    try:
        conn.executescript(
            """
            CREATE TABLE requests(request_id TEXT PRIMARY KEY);
            """
        )
        # Attach two source DBs
        conn.execute("ATTACH DATABASE ? AS db1", (db_files[0],))
        conn.execute("ATTACH DATABASE ? AS db2", (db_files[1],))
        cur = conn.execute("SELECT (SELECT COUNT(*) FROM db1.requests) + (SELECT COUNT(*) FROM db2.requests)")
        total = int(cur.fetchone()[0])
        assert total == 5  # 2 + 3 rows as created above
    finally:
        conn.close()


