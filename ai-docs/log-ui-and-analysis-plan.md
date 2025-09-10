# Log UI & Analysis System Plan (Separate API + Web GUI)

## Objectives
- **Operator UX**: Pleasant, readable views with syntax highlighting, collapsing long parts, grouping by dialogs/keys.
- **Dual sources**: Primary from SQLite partitions; optional fresh text logs for emergency viewing.
- **Remote connectivity**: Web UI can connect to local or remote API; user provides base URL + API key stored in browser.
- **Secure separation**: Distinct API keys from proxy; configured via `.env`, with dummy in `.env.example`.
- **Single IP hosting**: Serve multiple APIs and the GUI on the same IP via Traefik routers/paths/hosts.
- **Ops parity**: All CLI logdb features invocable from the GUI via API.
- **Testability**: Unit tests (API, GUI), integration tests (API↔DB, GUI↔API), and E2E flows.

## Decision Summary
- **Backend Service**: New service `ai_proxy_ui` using Python 3.10+, FastAPI, Pydantic, Uvicorn (consistent with main project). Reuse `ai_proxy.logdb` modules to query SQLite partitions.
- **Auth**: API key auth (Bearer) with separate key sets: `LOGUI_API_KEYS` (user/read) and `LOGUI_ADMIN_API_KEYS` (admin). No reuse of proxy keys. Minimal RBAC with roles `user` and `admin` enforced by key set.
- **CORS**: Configurable `LOGUI_ALLOWED_ORIGINS` for Web UI origins; by default allow `https://logs.$DOMAIN` and `http://localhost:5173` (dev).
- **API Versioning**: Public API under `/ui/v1/...` with OpenAPI at `/ui/v1/openapi.json`. Swagger UI disabled by default in prod or gated behind admin auth; enabled in dev.
- **DB Access**: Read-only by default for query endpoints; open partitions with `mode=ro` and `immutable=1` when safe; write ops only through explicit admin endpoints that wrap existing `logdb` functionality safely.
- **Live tail**: Server-Sent Events (SSE) or WebSocket for raw text tailing; rate-limited and feature-flagged.
- **Frontend**: React + TypeScript + Vite; UI lib: Mantine (or Chakra) + TanStack Table + React Router; syntax highlight: `prismjs` via `react-syntax-highlighter`; virtualization via `react-virtual`.
- **HTTP Client**: `ky` (fetch wrapper) with bearer injection from localStorage.
- **Filesystem Safety**: Raw logs access constrained under `LOGUI_TEXT_LOG_DIR` with strict path traversal protections (no `..`, no absolute paths; symlinks resolved and validated inside root).
- **Testing**: API - `pytest`, `httpx.AsyncClient`, `pytest-asyncio`; GUI - `vitest`, `@testing-library/react`; E2E - Playwright (Dockerized). CI runs tests via Docker.
- **Deployment**: Traefik host/path routing: API at `https://logs-api.$DOMAIN` (or `/logs/api`), GUI at `https://logs.$DOMAIN` (or `/logs/ui`). Static GUI served by Nginx or FastAPI static hosting; prefer Nginx container for caching. Configure SSE/WebSocket friendly timeouts in Traefik.

## Environment Variables (new)
- `LOGUI_API_KEYS` (required): Comma-separated list of API keys for UI API.
- `LOGUI_ADMIN_API_KEYS` (optional but recommended): Comma-separated list of admin keys for privileged endpoints. If unset, admin endpoints are disabled.
- `LOGUI_ALLOWED_ORIGINS` (optional): CSV list of allowed origins for CORS.
- `LOGUI_ENABLE_TEXT_LOGS` (default: `false`): Enable raw text log browsing.
- `LOGUI_TEXT_LOG_DIR` (default: `./logs`): Directory with raw text logs.
- `LOGUI_SSE_HEARTBEAT_MS` (default: `15000`): SSE keepalive.
- `LOGUI_RATE_LIMIT_RPS` (default: `10`): Simple rate limiting per key.
- `LOGUI_DB_ROOT` (default: `./logs/db`): Root directory for SQLite partitions.

Add dummy placeholders to `.env.example` and document in `README.md`/`DEVELOPMENT.md` during early stages.

## API Surface (Initial)
- `GET /ui/health` — Health check (alias for backward compatibility).
- `GET /ui/v1/health` — Primary health check (versioned).
- `GET /ui/v1/config` — Returns server-side feature flags (e.g., text logs enabled, FTS availability) and API version.
- `GET /ui/v1/requests` — Paginated requests with filters: `since`, `to`, `model`, `status`, `endpoint`, `api_key_hash`, `dialog_id`, `limit`, `cursor`.
- `GET /ui/v1/requests/{request_id}` — Full request + response JSON, metadata.
- `GET /ui/v1/search` — FTS search when enabled: `q`, optional `role`, `model`, `endpoint`, `since`, `to`.
- `GET /ui/v1/dialogs` — Aggregates by `dialog_id` with counts/time range; filters as above.
- `GET /ui/v1/raw/logs` — List raw files (only if `LOGUI_ENABLE_TEXT_LOGS=true`).
- `GET /ui/v1/raw/tail` — SSE/WebSocket tail; params `file`, `lines`, `follow` (feature-flagged).
- Admin ops (wrap `logdb`):
  - `POST /ui/v1/admin/ingest` — body: `{from_dir, since, to}`
  - `POST /ui/v1/admin/fts/build` — `{since, to}`
  - `POST /ui/v1/admin/fts/drop` — `{since, to}`
  - `POST /ui/v1/admin/dialogs/assign` — `{since, to, window}`
  - `POST /ui/v1/admin/dialogs/clear` — `{since, to}`
  - `POST /ui/v1/admin/bundle/create` — `{since, to, out, include_raw}`
  - `POST /ui/v1/admin/bundle/verify` — `{path}`
  - `POST /ui/v1/admin/bundle/import` — `{path, dest}`
  - `POST /ui/v1/admin/merge` — `{from_dir, to_file}`
- `GET /ui/v1/admin/jobs` — Query background job statuses/logs.

Admin endpoints require admin-level auth via `LOGUI_ADMIN_API_KEYS`. No header-only elevation; RBAC enforced by key set.

Swagger/OpenAPI:
- `GET /ui/v1/openapi.json` — OpenAPI spec (always available).
- Swagger UI available at `/ui/v1/docs` in development; in production, disabled by default or gated by admin auth.

## GUI Surface (Initial)
- Connection Manager: Prompt for `baseURL` and `apiKey`; store in `localStorage` (`aiProxyLogs.baseUrl`, `aiProxyLogs.apiKey`). Support multiple saved targets.
- Pages:
  - Dashboard (basic stats, recent errors)
  - Requests (table with filters, pagination, selections)
  - Request Details (formatted JSON with highlighting, collapsible long fields)
  - Search (FTS minimal)
  - Dialogs (grouped view)
  - Raw Logs (optional): file picker + tail viewer
  - Admin (buttons/forms for logdb tasks with progress)
  - Settings (server selection, theme, preferences)

## Security & Access Control Additions
- RBAC: Keys in `LOGUI_ADMIN_API_KEYS` grant `admin` role; keys in `LOGUI_API_KEYS` grant `user` role. Admin-only routes under `/ui/v1/admin/*` require `admin`.
- Error schema: Standardized error body `{ code, message, details?, requestId }` for 4xx/5xx. Include `X-API-Version` and `X-Request-Id` headers in responses.
- Swagger protection: Disable Swagger UI in prod by default; enable with env flag (dev) or require admin auth when enabled.
- Path traversal defenses: Raw logs endpoints validate `file` within `LOGUI_TEXT_LOG_DIR` after realpath resolution; reject symlinks that escape root.
- Rate limiting: Separate stricter limits for `/ui/v1/raw/tail`. Return `Retry-After` headers on 429.

## Data/Query Patterns
- Cursor-based pagination using `(ts, request_id)` composite cursor for stable ordering.
- Query planner hints via indexes already present; attach multiple partitions for cross-range queries.
- FTS optional: only expose `/ui/search` when `LOGDB_FTS_ENABLED=true` on the server.

---

## Staged Plan (independent, testable; prioritize early API↔GUI touch)

### Stage U1 — Repository & Service Scaffolding
- Deliverables:
  - New Python package `ai_proxy_ui` (FastAPI app, auth middleware, CORS, config).
  - New `ui/` (React+TS+Vite), basic layout, connection manager stub.
  - Docker Compose services: `logs-ui-api`, `logs-ui-web` (Nginx), routed via Traefik.
  - `.env` additions with dummies in `.env.example`.
  - Dockerfiles: API (uvicorn) and Web (multi-stage Vite build → Nginx). Nginx config with cache headers and gzip/brotli.
  - Traefik labels for host- and path-based routing; SSE/WebSocket timeouts configured.
- Acceptance:
  - [ ] `GET /ui/v1/health` returns `{status:"ok"}`; `/ui/health` alias works.
  - [ ] GUI served at `/` shows Connect screen.
  - [ ] Traefik routes both services on same IP (host/path).
- Tests:
  - [ ] API unit: health, CORS, auth middleware rejects missing/invalid key.
  - [ ] GUI unit: renders Connect screen; stores creds to localStorage.
  - [ ] Integration: docker-compose up; Playwright checks Connect page loads.

### Stage U2 — AuthN/Z & Config Endpoint
- Deliverables:
  - Bearer auth with `LOGUI_API_KEYS` (user) and `LOGUI_ADMIN_API_KEYS` (admin); rate limit per key; `GET /ui/v1/config` exposes server flags and API version.
  - RBAC middleware: enforce admin-only for `/ui/v1/admin/*`.
  - OpenAPI served at `/ui/v1/openapi.json`; Swagger UI gated in prod.
  - Standard error schema responses; include `X-API-Version`, `X-Request-Id` headers.
  - GUI Connect flow: save `baseURL` + `apiKey`; test connection to `/ui/v1/health`.
- Acceptance:
  - [ ] Requests without/invalid key → 401.
  - [ ] User key → 200 for user endpoints, 403 for admin endpoints.
  - [ ] Admin key → 200 for admin endpoints.
  - [ ] Swagger UI inaccessible in prod without admin auth.
  - [ ] GUI shows connected target badge.
- Tests:
  - [ ] API unit: auth middleware, RBAC, rate-limiting, error schema.
  - [ ] GUI unit: connection form; error state on 401.
  - [ ] E2E: user enters server + key; sees “Connected”.

### Stage U3 — Requests Listing (DB-backed, minimal)
- Deliverables:
  - `GET /ui/requests` with filters (`since`, `to`, `limit`, `cursor`).
  - GUI table: columns ts, endpoint, model, status, latency; basic filters (date range), pagination.
- Acceptance:
  - [ ] Query spans multiple partitions by attaching DBs based on date range.
  - [ ] Stable cursor pagination; consistent order by `(ts DESC, request_id DESC)`.
  - [ ] GUI lists first page and paginates.
- Tests:
  - [ ] API unit: partition resolution; pagination with stable `(ts, request_id)` ordering and server caps; filter correctness.
  - [ ] Integration: sample fixtures for 2 days; counts match.
  - [ ] GUI unit: renders rows; pagination buttons operate.

### Stage U4 — Request Details View
- Deliverables:
  - `GET /ui/requests/{request_id}` with full JSON payloads.
  - GUI: JSON pretty view with syntax highlighting; collapsible long arrays/strings; copy buttons.
- Acceptance:
  - [ ] Large payloads render with collapse-by-default beyond threshold.
  - [ ] Syntax highlighting works for JSON and code-like strings.
- Tests:
  - [ ] API unit: 404 on missing; payload round-trip.
  - [ ] GUI unit: expand/collapse logic; copy.
  - [ ] E2E: navigate from list to details and back.

### Stage U5 — Dialog Grouping & Aggregations
- Deliverables:
  - `GET /ui/dialogs` aggregate by `dialog_id` with counts, start/end times.
  - GUI: Dialogs view; click-through to dialog’s requests subset.
- Acceptance:
  - [ ] Dialogs list respects filters; count/time range accurate.
  - [ ] Cross-linking to filtered requests view.
- Tests:
  - [ ] API unit: SQL aggregation correctness, indexes used.
  - [ ] GUI unit: grouping table and navigation.
  - [ ] Integration: verify sample dialog grouping dataset.

### Stage U6 — Minimal FTS Search
- Deliverables:
  - `GET /ui/search?q=...` (enabled only if `LOGDB_FTS_ENABLED=true`). Supports proximity ops minimally.
  - GUI: Search page with simple query box and results linking to requests.
- Acceptance:
  - [ ] When FTS disabled → 404 or 400; GUI hides feature.
  - [ ] Queries return results with `request_id` joinable to `requests`.
- Tests:
  - [ ] API unit: guard on flag; FTS query correctness on fixtures.
  - [ ] GUI unit: search form, empty-state handling.
  - [ ] Integration: round-trip from search → details.

### Stage U7 — Raw Text Logs (Optional, Feature-flagged)
- Deliverables:
  - `GET /ui/raw/logs` list; `GET /ui/raw/tail` SSE/WebSocket with `file`, `lines`, `follow`.
  - GUI: Raw Logs page with file picker and live tail.
- Acceptance:
  - [ ] Feature toggled by `LOGUI_ENABLE_TEXT_LOGS`.
  - [ ] SSE heartbeat; safe truncation; max line caps; backpressure handling.
  - [ ] Path traversal attempts are rejected; only files under `LOGUI_TEXT_LOG_DIR` are accessible.
- Tests:
  - [ ] API unit: tailing abstraction, rate-limit; 404 for missing file; traversal/escape attempts return 400/403.
  - [ ] GUI unit: SSE handling, disconnect/reconnect logic.
  - [ ] E2E: view tail output on a small fixture.

### Stage U8 — Admin Ops (Wrap logdb)
- Deliverables:
  - Admin endpoints mapping to CLI features; background job manager (in-memory queue with persistence of last N runs).
  - GUI Admin page to trigger ops and show progress/logs.
- Acceptance:
  - [ ] Idempotent operations; safe argument validation.
  - [ ] Progress endpoint streams job logs (SSE) and final status.
- Tests:
  - [ ] API unit: RBAC enforcement; parameter validation; job lifecycle; error propagation; checksum verification for bundles before import.
  - [ ] Integration: stubbed small dataset for ingest→fts→dialogs sequence.
  - [ ] GUI unit: form validation; job status UI.
  - [ ] E2E: trigger ingest, observe completion state.

### Stage U9 — Security Hardening & Audit
- Deliverables:
  - Request logging for UI API, masked secrets; rate limits; CORS tightened to configured origins; optional IP allowlist.
  - Audit trail for admin ops.
  - Security headers (CSP, HSTS, X-Content-Type-Options, Referrer-Policy) via Nginx and/or FastAPI.
  - Swagger UI restricted or disabled in prod.
- Acceptance:
  - [ ] Keys never logged; headers sanitized.
  - [ ] CORS rejects disallowed origins.
  - [ ] Security headers present in responses from web and API services.
- Tests:
  - [ ] API unit: CORS matrix; masking checks; security headers check.
  - [ ] Integration: rate-limit behavior.

### Stage U10 — Deployment Integration
- Deliverables:
  - Traefik rules for API + GUI on same IP (host or path based); HTTPS via existing automation.
  - Makefile targets to build, run, test UI.
- Acceptance:
  - [ ] `docker compose up` serves GUI at `https://logs.$DOMAIN` and API at `https://logs-api.$DOMAIN` (or `/logs/...`).
  - [ ] Health and GUI functional.
- Tests:
  - [ ] Smoke: `./scripts/test-https.sh` extended for UI endpoints.
  - [ ] Playwright: load GUI behind HTTPS.

### Stage U11 — Performance & UX Polish
- Deliverables:
  - Virtualized tables; debounced filters; save table state per user in localStorage.
  - API query caps; pagination sizes; N+1 avoided; indexes reviewed.
- Acceptance:
  - [ ] 50k rows page/scroll smoothly (<60ms frame budget) on dev laptop.
  - [ ] API requests under 300ms p95 on common filters (local).
- Tests:
  - [ ] GUI perf harness (basic): virtualized list test.
  - [ ] API profiling notes; SQL query plans checked in docs.

### Stage U12 — Documentation & Samples
- Deliverables:
  - README updates; `.env.example` populated; screenshots; curl examples; GUI user guide.
- Acceptance:
  - [ ] New joiner can deploy and connect to remote in <10 minutes.
- Tests:
  - [ ] None automated; peer review checklist.

---

## Traefik Routing (One IP, multiple services)
- Host-based (recommended):
  - GUI: `logs.$DOMAIN` → `logs-ui-web`
  - API: `logs-api.$DOMAIN` → `logs-ui-api`
- Path-based (alternative):
  - GUI: `/$BASE_PATH/ui` → `logs-ui-web`
  - API: `/$BASE_PATH/api` → `logs-ui-api`

Both options align with existing router; ensure CORS `origin` reflects GUI host.

### Traefik labels and timeouts
- Configure SSE/WebSocket friendly timeouts (e.g., `serversTransport.forwardingTimeouts.readTimeout`, `responseHeadersTimeout`).
- Enable compression and proper forwarded headers.
- Provide labels for both host- and path-based routing; document examples in Compose.

---

## Testing Strategy (Holistic)
- API Unit: `pytest`, `httpx` test client, `pytest-asyncio`; fixtures for sample partitions under `tests/fixtures/logdb/`.
- GUI Unit: `vitest` + `@testing-library/react`; mock `ky` client.
- Integration: Docker Compose with SQLite sample DBs; tests that hit API against real files.
- E2E: Playwright flows: connect → list → details → search → dialogs → admin op. Run Playwright inside a Docker image with browsers; export artifacts on failure.
- CI: Extend `Makefile` with `make ui-test`, `make ui-build`, and add to `ci` target; run Vitest and Playwright in Docker containers only.

---

## Risk Management
- Large payload rendering → collapse & lazy JSON sections, code-split heavy components.
- FTS absence → guard endpoints; GUI hides features dynamically from `/ui/config`.
- Long-running admin ops → background jobs with SSE updates and cancel where safe.
- Secret handling in browser → store only API key locally; never send to third parties; allow quick switch/clear.

---
