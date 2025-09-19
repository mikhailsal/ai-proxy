### Outbound Adapter Logging – End‑to‑End Implementation Plan

Goal: Add precise logging of provider-bound (outgoing) requests and provider responses at the adapter level, ingest them into SQLite via logdb, and surface them in the Logs UI API and React app.

Scope covers `ai_proxy/` (adapters + logging), `ai_proxy/logdb/` (schema + ingest), `ai_proxy_ui/` (API responses), and `ui/` (React UI).

Notes
- Aligns with existing docs: `ai-docs/log-storage-migration-plan.md` and `ai-docs/log-ui-and-analysis-plan.md`.
- Security: redact secrets in headers/bodies before logging; cap payload sizes.
- Backward compatible: old logs/DBs remain valid; new columns are nullable.

---

### Stage L1 — Adapter Instrumentation (Structured Outbound/Inbound Logging)

Deliverables
- Structured logs for each provider call containing sanitized outbound request and inbound response.
- New helper in `ai_proxy.logging.config` to log provider exchanges.

Tasks
1) Add redaction and size-capping utilities
- File: `ai_proxy/logging/config.py`
- Add `sanitize_headers(dict) -> dict` (redact keys: authorization, cookie, set-cookie, proxy-authorization, x-api-key, api_key, bearer, token, secret, key, client_secret, access_token, refresh_token; case-insensitive).
- Add `truncate_text(value: str, max_bytes=131072) -> str` and `truncate_json(obj, max_bytes=131072) -> obj` (preserve JSON type; cap total serialized size; mark as truncated).

Acceptance
- [ ] Unit: sanitizer redacts known secret keys.
- [ ] Unit: truncator caps payload near limit and marks truncation.

2) Add provider-exchange logger
- File: `ai_proxy/logging/config.py`
- Add `get_provider_logger(provider_name: str)` writing to `logs/providers/{provider}.log` (pattern similar to `get_model_logger`).
- Add `log_provider_exchange(...)` with shape:
  - Common: timestamp, endpoint, provider, model_original, model_mapped, api_key_hash, latency_ms, status_code, request_id_hint (optional), streaming (bool).
  - Outbound: url, method, headers_sanitized, body_sanitized (json if possible else text), timeout.
  - Inbound: status_code, headers_sanitized, body_sanitized (json/text), error if any.
- Also mirror a concise entry to endpoint log (same file as `log_request_response`) under event name `Provider Exchange`.

Acceptance
- [ ] Log files created under `logs/providers/*.log`.
- [ ] Entry includes both outbound and inbound blocks when available.
- [ ] JSON is valid; no secrets present in headers; large bodies truncated.

3) Instrument adapters
- File: `ai_proxy/adapters/openrouter.py`
  - Before `self.client.post(...)`: compute absolute URL, build headers; call `log_provider_exchange(..., phase="outbound", ...)`.
  - After response: parse JSON if possible; call `log_provider_exchange(..., phase="inbound", ...)` with status and body.
  - Streaming path: emit `phase="stream_start"` at start and `phase="stream_end"` with final status/summary. For debugging, add env flag `PROVIDER_STREAM_DEBUG_LOG=true` to enable per-chunk logging (emit `phase="stream_chunk"` for each chunk, size-capped and sampled if too frequent; default: false to avoid backpressure).
- File: `ai_proxy/adapters/gemini.py`
  - Log the transformed `gemini_request` (types -> dict) as outbound (redacted/truncated).
  - Non-streaming: log inbound response JSON.
  - Streaming: analogous to OpenRouter with start/end and summary, including optional per-chunk debug logging via env flag.
- Optional: move duplicated code to `ai_proxy/adapters/base.py` helper methods (e.g., `_log_outbound(...)`, `_log_inbound(...)`).

Acceptance
- [ ] Non-streaming provider calls yield two entries (outbound + inbound) in provider logs.
- [ ] Streaming calls yield start/end entries; no unbounded logging per chunk by default.
- [ ] On provider error/exception, an inbound entry with `error` is recorded.

Tests
- [ ] Unit (adapter-level): logger called with expected fields (use monkeypatch to capture calls).
- [ ] Integration: run a fake call (mock httpx/genai); verify files under `logs/providers/` with sanitized content.
- [ ] Performance: Measure logging overhead with/without debug mode using timed mock requests (ensure <5% latency increase).
- [ ] Edge-case: Test large payload truncation, redaction of custom keys via env regex, and streaming with high chunk frequency (verify sampling/backpressure handling).

---

### Stage L2 — LogDB Schema & Ingestion (Store Provider Exchanges)

Deliverables
- Schema extended with optional columns for provider exchange details.
- Importer captures new fields from structured logs; backward compatible.

Tasks
1) Extend schema
- File: `ai_proxy/logdb/schema.py`
- Table `requests` add nullable columns:
  - `provider TEXT NULL`
  - `provider_url TEXT NULL`
  - `provider_method TEXT NULL`
  - `provider_out_headers_json TEXT NULL`
  - `provider_out_body_json TEXT NULL`
  - `provider_in_status_code INTEGER NULL`
  - `provider_in_headers_json TEXT NULL`
  - `provider_in_body_json TEXT NULL`

Acceptance
- [ ] Fresh init creates columns.
- [ ] PRAGMA integrity_check = ok.

2) Backward-compatible migration at ingest time
- File: `ai_proxy/logdb/processing/batch_processor.py`
- On open connection, detect if columns are missing; `ALTER TABLE` to add columns if needed before inserts.

Acceptance
- [ ] Ingest into existing partitions without prior migration succeeds.

3) Parse new fields from logs
- File: `ai_proxy/logdb/parsers/log_parser.py`
- Accept entries that include extra keys under `provider_exchange`: { provider, url, method, out_headers, out_body, in_status_code, in_headers, in_body }.
- Keep current requirement for `request` and `response` intact.
- Normalize and serialize the extra fields into the new columns (JSON strings for headers/body, already sanitized in L1).

Acceptance
- [ ] Unit: entries without provider fields still parse.
- [ ] Unit: entries with provider fields serialize into new columns.

4) Inserter wiring
- File: `ai_proxy/logdb/processing/batch_processor.py`
- Extend `INSERT OR IGNORE` column list to include new columns (presence-gated).

Acceptance
- [ ] New columns populated for new logs; NULL for old ones.

Optional
- Update `ai_proxy/logdb/fts.py` to optionally index text from `provider_in_body_json` and `provider_out_body_json` (flag-protected to avoid size bloat).

Tests
- [ ] Unit: schema detection + ALTER at runtime.
- [ ] Unit: parser normalize with/without provider fields.
- [ ] Integration: ingest sample log lines containing provider exchange; SELECT shows populated columns.

---

### Stage L3 — Logs UI API (Expose Provider Exchanges)

Deliverables
- `ai_proxy_ui` API surfaces provider exchange details in request details endpoint and filters.

Tasks
1) Extend request details response
- File: `ai_proxy_ui/routers/requests.py`
- In `get_request_details`:
  - Add selected columns to SQL and response body: `provider, provider_url, provider_method, provider_out_headers_json, provider_out_body_json, provider_in_status_code, provider_in_headers_json, provider_in_body_json`.
  - JSON-decode JSON columns where possible.

Acceptance
- [ ] `GET /ui/v1/requests/{request_id}` returns new fields when present.

2) Add optional filters to listing
- File: `ai_proxy_ui/routers/requests.py`
- In `list_requests`: add optional `provider` and `status` (provider inbound status) filters. Keep indexes in mind (status filter maps to `provider_in_status_code`).

Acceptance
- [ ] Filter by `provider` narrows results.
- [ ] Filter by inbound status narrows results.

3) Config endpoint update
- File: `ai_proxy_ui/main.py`
- In `GET /ui/v1/config`, add capability flags (e.g., `provider_exchange_enabled: true`).

Acceptance
- [ ] Config reflects feature availability.

Tests
- [ ] API unit: details endpoint includes fields; missing columns handled gracefully.
- [ ] API unit: listing filters work.
- [ ] Integration: attach a partition with provider data and read via API.

---

### Stage L4 — React UI (Render Provider Exchanges)

Deliverables
- Request Details page shows provider outbound/inbound sections with JSON and headers; copy and collapse controls.

Tasks
1) Extend Request Details view
- Dir: `ui/src/`
- Update `RequestDetails` (or equivalent) to render:
  - "Outbound to Provider" — URL, method, headers (redacted), JSON body (pretty, collapsible, copy).
  - "Inbound from Provider" — status code, headers, JSON body (pretty, collapsible, copy).
  - Handle absence of fields gracefully (show info alert).

Acceptance
- [ ] Large bodies are collapsed by default; expand works.
- [ ] Copy buttons copy JSON.

2) Requests table enhancements (optional)
- Add columns/badges for `provider` and `provider_in_status_code`.

Acceptance
- [ ] Provider badge displays when available; table remains performant.

Tests
- [ ] GUI unit (Vitest): components render with/without provider fields, collapse/expand, copy.
- [ ] E2E (Playwright): open a request with provider data and view sections.

---

### Stage L5 — End-to-End Flow & Documentation

Deliverables
- Sample logs → ingest → UI read.
- Documentation of fields, redaction, and troubleshooting.

Tasks
1) End-to-end validation
- Generate sample provider-exchange logs locally by calling `/v1/chat/completions` against a mock provider.
- Run `logdb ingest` for the date range.
- Query via `ai_proxy_ui` API and verify UI shows the new sections.

Acceptance
- [ ] End-to-end scenario works and is repeatable on a dev laptop.
- [ ] Performance: Run E2E with multiple concurrent requests; verify no significant slowdown from logging.
- [ ] Edge-case: Test with oversized responses, errors mid-stream, and debug mode enabled; confirm logs are complete without overload.

2) Docs
- File: `ai-docs/`
- Add a short section to `log-storage-migration-plan.md` describing new columns and ingest migration.
- Add a section to `log-ui-and-analysis-plan.md` documenting API fields and UI rendering rules.
- This plan file: keep updated with status.

Acceptance
- [ ] Docs describe redaction policy and payload size caps.

---

### Security, Privacy, and Stability Considerations
- Redaction: mandatory on sensitive header/body keys; add tests.
- Size guard: body caps to 128 KiB serialized per direction; streams logged at start/end only by default.
- PII/Secrets: optional regex list in env to redact additional keys; document env var.
- Failure isolation: logging failures must not break request flow; wrap in try/catch and degrade to minimal events.
- Backpressure: no per-chunk streaming logs unless explicitly enabled for debugging via `PROVIDER_STREAM_DEBUG_LOG=true` (document risks and use for short debugging sessions only).

---

### Rollout Strategy
- Feature flags: `PROVIDER_LOGGING_ENABLED` (default true for adapters), `LOGDB_FTS_INCLUDE_PROVIDER_BODIES` (default false).
- Safe deploy order: L1 → L2 → L3 → L4.
- Backfill: not required; old rows simply have NULLs.

---

### Traceability to Code (planned edit points)
- `ai_proxy/logging/config.py`: sanitizer, truncators, provider logger, log_provider_exchange.
- `ai_proxy/adapters/base.py`: optional shared helpers.
- `ai_proxy/adapters/openrouter.py`: outbound/inbound logging.
- `ai_proxy/adapters/gemini.py`: outbound/inbound logging.
- `ai_proxy/logdb/schema.py`: new columns.
- `ai_proxy/logdb/parsers/log_parser.py`: parse provider_exchange.* fields.
- `ai_proxy/logdb/processing/batch_processor.py`: migration + INSERT columns.
- `ai_proxy_ui/routers/requests.py`: SQL columns in details; filters in listing.
- `ai_proxy_ui/main.py`: config flag.
- `ui/src/*`: Request Details UI; optional list enhancements.

---

### Verification Checklist (global)
- [ ] Adapters emit sanitized, size-capped provider exchange logs.
- [ ] Importer stores provider columns into SQLite (new and existing partitions).
- [ ] UI API exposes provider exchange fields.
- [ ] React UI renders provider outbound/inbound sections.
- [ ] Secrets never appear in logs; tests cover redaction.
- [ ] Performance acceptable (no noticeable overhead in hot path; capped IO).
