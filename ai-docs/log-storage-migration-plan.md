# Log Storage Upgrade Plan (SQLite + FTS5 with Log Bundles)

## Objectives
- **Portability**: Logs are easy to move between prod/local/other servers.
- **Robustness**: Idempotent ingestion; verifiable integrity; safe resume.
- **Low overhead**: No extra services; low CPU/RAM; Docker tests unchanged.
- **Searchability**: Fast full‑text search; grouping by dialogue.
- **Backward compatibility**: Existing text logs remain the source during rollout.

## Decision Summary
- **Storage**: SQLite 3 with JSON1 + FTS5.
- **Partitioning**: Time‑based, default daily files under `logs/db/YYYY/MM/ai_proxy_YYYYMMDD.sqlite3`.
- **Transfer**: Tar+gzip bundles (Log Bundle v1) with `metadata.json` + SHA‑256 checksums.
- **Ingestion**: Offline importer reads existing structured text logs incrementally.

## Feature Flags (toggle per stage; keep system working if disabled)
- `LOGDB_ENABLED` (default: `false`) — enables importer and DB outputs.
- `LOGDB_PARTITION_GRANULARITY` (default: `daily`) — `daily|weekly`.
- `LOGDB_FTS_ENABLED` (default: `false`) — build FTS5 index.
- `LOGDB_GROUPING_ENABLED` (default: `false`) — compute heuristic `dialog_id`.
- `LOGDB_BUNDLE_INCLUDE_RAW` (default: `false`) — include raw `.log` files in bundles.
- `LOGDB_IMPORT_PARALLELISM` (default: `2`) — concurrent file parses.

All flags must be read only by tooling/cron, not by the running API, to avoid runtime coupling.

## Staged Plan (independently testable; can be paused safely)

### Stage A — Schema & Partitioning
- Deliverables:
  - SQLite schema file creator with JSON1/FTS5 detection.
  - Partition layout `logs/db/YYYY/MM/ai_proxy_YYYYMMDD.sqlite3`.
- Implementation outline:
  - Enable WAL; set `synchronous=NORMAL` during batch; `NORMAL`→`FULL` after.
  - Tables:
    - `servers(server_id TEXT PK, hostname TEXT, env TEXT, first_seen_ts INTEGER)`
    - `requests(request_id TEXT PK, server_id TEXT, ts INTEGER, endpoint TEXT, model_original TEXT NULL, model_mapped TEXT NULL, status_code INTEGER, latency_ms REAL, api_key_hash TEXT NULL, request_json TEXT, response_json TEXT, dialog_id TEXT NULL)`
    - `ingest_sources(source_path TEXT PK, sha256 TEXT, bytes_ingested INTEGER, mtime INTEGER, last_scan_ts INTEGER)`
  - Indexes: `requests(ts)`, `requests(endpoint)`, `requests(status_code)`, `requests(model_original)`, `requests(model_mapped)`, `requests(api_key_hash)`.
  - FTS table (created in Stage D when flag enabled): `request_text_index`.
- Acceptance checklist:
  - [x] Schema can be created on an empty DB file.
  - [x] PRAGMA `integrity_check` returns `ok`.
  - [x] WAL mode active; `journal_mode=WAL`.
  - [x] Partition path is created for the current day with correct permissions.
- Tests:
  - [x] Unit: schema creation; presence of tables/indexes.
  - [x] Unit: PRAGMA checks; WAL on.
  - [x] Integration: create two partitions (today/yesterday) and open both.
- Rollback:
  - [x] Remove generated DB files; no impact to running API (still writes text logs).

### Stage B — Importer (Parser + Normalizer + Inserter)
- Deliverables:
  - [x] CLI `logdb ingest --from logs/ --since YYYY-MM-DD --to YYYY-MM-DD`.
  - [x] Incremental ingestion using `ingest_sources` checkpoints.
- Implementation outline:
  - Parse existing endpoint/model logs under `logs/` line‑by‑line.
  - Extract JSON payload after the `asctime - level -` prefix; validate fields.
  - Compute `request_id = sha256(server_id|ts_iso|endpoint|sha256(req)|sha256(resp))`.
  - Batch insert with `INSERT OR IGNORE`.
- Acceptance checklist:
  - [x] First run ingests sample files and reports counters.
  - [x] Second run ingests 0 new rows (idempotent).
  - [x] Checkpoint in `ingest_sources` reflects `bytes_ingested` and `mtime`.
- Tests:
  - [x] Unit: parser tolerates minor noise/rotation.
  - [x] Integration: ingest two rotated files; resume after interruption.
  - [x] Integration: duplicate lines produce no duplicates in `requests`.
- Rollback:
  - [x] Delete created partitions; importer can be re‑run safely.

### Stage C — Server Identity & Deduplication
- Deliverables:
  - Stable `server_id` per host (UUID stored once), included in importer context.
- Acceptance checklist:
  - [ ] `servers` row created on first run; reused on later runs.
  - [ ] Same logs ingested on different machines with same `server_id` stay deduped.
- Tests:
  - [ ] Unit: deterministic `server_id` derivation from hostname/env or persisted file.
  - [ ] Integration: simulate two hosts; verify dedupe via `request_id`.

### Stage D — FTS5 Full‑Text Index
- Deliverables:
  - Virtual table `request_text_index` with columns: `request_id, role, content, endpoint, model_original, model_mapped`.
  - Populator extracts text from `request_json.messages[].content` and primary response text.
- Acceptance checklist:
  - [ ] FTS enabled only if `LOGDB_FTS_ENABLED=true`.
  - [ ] Queries like `SELECT * FROM request_text_index WHERE request_text_index MATCH 'timeout NEAR/3 retry';` return expected hits.
  - [ ] Size overhead remains within agreed limit (<2× raw rows for test set).
- Tests:
  - [ ] Unit: extractor handles multimodal/non‑text content safely.
  - [ ] Integration: highlight/rowids map back to `requests`.
- Rollback:
  - [ ] Drop/recreate FTS table without affecting `requests`.

### Stage E — Dialogue Grouping (Heuristic)
- Deliverables:
  - Offline grouper that assigns `dialog_id` using sliding window (default 30m), grouped by `api_key_hash+endpoint+model_mapped`.
- Acceptance checklist:
  - [ ] Enabled only if `LOGDB_GROUPING_ENABLED=true`.
  - [ ] Sequences within window share one `dialog_id`; gaps beyond window split.
  - [ ] Re‑running grouper is idempotent and stable.
- Tests:
  - [ ] Synthetic timeline validates window boundaries.
  - [ ] Mixed models/endpoints create distinct dialogs.
- Rollback:
  - [ ] Clear `dialog_id` column; no impact on base queries.

### Stage F — Bundle Create & Verify (Log Bundle v1)
- Deliverables:
  - `logdb bundle create --since ... --to ... --out bundle.tgz`.
  - `logdb bundle verify bundle.tgz`.
- Bundle structure:
  - `metadata.json`: `{ bundle_id, created_at, server_id, schema_version, files: [{path, sha256, bytes}], include_raw }`.
  - `db/` with `.sqlite3` partitions; optional `raw/` with `.log` if flag enabled.
- Acceptance checklist:
  - [ ] Verify recomputed SHA‑256 matches `metadata.json`.
  - [ ] Tampering a file causes verification to fail.
  - [ ] Bundle size within expected range for sample dataset.
- Tests:
  - [ ] Unit: metadata schema and checksum calc.
  - [ ] Integration: create→verify→tamper→verify fails.

### Stage G — Bundle Import & Merge
- Deliverables:
  - `logdb bundle import bundle.tgz --dest logs/db/` (copy new partitions, skip existing).
  - Optional merge CLI: `logdb merge --from logs/db/2025/09 --to logs/db/monthly/2025-09.sqlite3`.
- Acceptance checklist:
  - [ ] Import is idempotent; re‑import does nothing.
  - [ ] Attached multi‑DB queries across partitions work.
  - [ ] Merge produces a compact file with same row counts (`INSERT OR IGNORE`).
- Tests:
  - [ ] Integration: ATTACH multiple partitions and run a cross‑range query.
  - [ ] Integration: pre/post merge counts equal; `integrity_check=ok`.

### Stage H — Transport (rsync/scp) & Integrity
- Deliverables:
  - Documented commands and helper scripts for secure transfer.
- Commands:
  - `rsync -azP --chmod=F640 --info=progress2 user@host:/var/app/logs/db/ ./logs/db/`
  - `scp -p user@host:/var/app/bundles/bundle-2025-09-01_10.tgz ./bundles/`
- Acceptance checklist:
  - [ ] Interrupted `rsync` resumes and final checksums match.
  - [ ] Post‑transfer `bundle verify` passes.
- Tests:
  - [ ] Manual/integration: simulate interruption; verify resume.

### Stage I — Performance & Resource Caps
- Deliverables:
  - Importer respects memory cap (<256MB) and reasonable throughput on low‑end VPS.
- Acceptance checklist:
  - [ ] 1M log lines ingest under target time (doc the target, e.g., <20 min) and RAM.
  - [ ] WAL checkpoints do not stall; DB stays queryable.
- Tests:
  - [ ] Stress: synthetic generator; measure RAM/time; assert thresholds.

### Stage J — Optional Explicit Dialog ID (App change; can defer)
- Deliverables:
  - If/when app emits `X-Dialog-Id` in logs, importer prefers explicit ID.
- Acceptance checklist:
  - [ ] Heuristic replaced only where explicit ID present.
  - [ ] Mixed datasets maintain stable grouping.
- Tests:
  - [ ] Fixture with explicit IDs; verify importer logic preference.

### Stage K — Ops Integration (Cron) & Retention
- Deliverables:
  - Cron or systemd timers on prod to run hourly ingest and daily bundle.
  - Retention policy doc: raw logs 7–30d, DB partitions per policy.
- Acceptance checklist:
  - [ ] Hourly ingest runs complete under time window; logs recorded.
  - [ ] Daily bundle produced and verified; alarms on verification failure.
  - [ ] Retention jobs rotate old raw logs and keep DB partitions as configured.
- Tests:
  - [ ] Dry‑run cron locally via container; verify logs/exit codes.

## Commands (reference; implement via CLI)
- Initialize schema: `logdb init --date 2025-09-10`
- Ingest: `logdb ingest --from ./logs/ --since 2025-09-01 --to 2025-09-10`
- Build FTS: `logdb fts build --since 2025-09-01 --to 2025-09-10`
- Group dialogs: `logdb dialogs assign --since 2025-09-01 --to 2025-09-10 --window 30m`
- Create bundle: `logdb bundle create --since 2025-09-01 --to 2025-09-10 --out ./bundles/b-2025-09-01_10.tgz`
- Verify bundle: `logdb bundle verify ./bundles/b-2025-09-01_10.tgz`
- Import bundle: `logdb bundle import ./bundles/b-2025-09-01_10.tgz --dest ./logs/db/`
- Merge: `logdb merge --from ./logs/db/2025/09 --to ./logs/db/monthly/2025-09.sqlite3`

## Appendix A — DB Schema (DDL sketch)
```sql
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
CREATE INDEX IF NOT EXISTS idx_requests_ts ON requests(ts);
CREATE INDEX IF NOT EXISTS idx_requests_endpoint ON requests(endpoint);
CREATE INDEX IF NOT EXISTS idx_requests_status ON requests(status_code);
CREATE INDEX IF NOT EXISTS idx_requests_model_orig ON requests(model_original);
CREATE INDEX IF NOT EXISTS idx_requests_model_mapped ON requests(model_mapped);
CREATE INDEX IF NOT EXISTS idx_requests_api ON requests(api_key_hash);
-- FTS built when LOGDB_FTS_ENABLED=true
-- CREATE VIRTUAL TABLE request_text_index USING fts5(
--   request_id UNINDEXED, role, content, endpoint, model_original, model_mapped
-- );
```

## Appendix B — Log Bundle v1
- `metadata.json` fields:
  - `bundle_id` (UUIDv4), `created_at` (ISO8601 UTC), `server_id`, `schema_version`.
  - `files`: list of `{ path, sha256, bytes }` for `db/*.sqlite3` (and `raw/*` if included).
  - `include_raw` (boolean).
- Verification: recompute SHA‑256 over file bytes and compare to metadata.

## Appendix C — Retention Policy (template)
- Raw logs: keep 14 days; rotate with size/time policy (current rotation stays).
- SQLite partitions: keep 12 months online; archive older to cold storage.
- Bundles: keep daily for 90 days; weekly/monthly thereafter.
