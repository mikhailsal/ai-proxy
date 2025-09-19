Streaming proxy: postmortem and remediation plan
==============================================

Author: AI assistant
Date: 2025-09-19

Summary
-------
This document describes the investigation, findings, fixes and recommended next steps
related to streaming (SSE) behavior for the `/v1/chat/completions` endpoint in the
`ai-proxy` project. It summarizes what went wrong, how we tested it, what we changed in
the codebase and how to prevent regressions in the future.

1. Background and initial symptom
--------------------------------
Users reported that functional streaming tests were passing but logs contained
non-streaming responses (final object `chat.completion` instead of `chat.completion.chunk`),
and sometimes the logged `response` contained only a short `"\n"` or empty content.
This mismatch raised suspicion that either the provider returned incorrect data, or the
proxy was aggregating and logging incorrectly (or we were testing an outdated image).

2. What we inspected
---------------------
- Tests: `tests/functional/test_openrouter.py`, `tests/functional/test_gemini.py`, unit tests
  around `chat_completions` (notably `tests/unit/api/test_chat_core.py`).
- Endpoint implementation: `ai_proxy/api/v1/chat_completions.py`.
- Adapters: `ai_proxy/adapters/openrouter.py` and `ai_proxy/adapters/gemini.py`.
- Routing: `ai_proxy/core/routing.py`.
- Logging: `ai_proxy/logging/config.py` and endpoint logs in `logs/v1_chat_completions.log`.
- Docker / CI flows: `docker-compose.test.yml`, `Makefile` test targets.

3. Key findings
----------------
- The functional test originally only checked HTTP status, `Content-Type: text/event-stream`,
  and that something was yielded; it did not verify that the streamed SSE events contained
  valid JSON chunks (`chat.completion.chunk`) with non-whitespace `delta.content`.
- The endpoint originally yielded provider generator output and tried to parse a single
  JSON object from each `chunk`; however, provider chunks could contain multiple SSE events
  (multiple `data: ...` lines in a single chunk) or leading comment lines like `: OPENROUTER PROCESSING`.
- The original parser treated the entire chunk as a single JSON payload which caused
  partial JSON or multiple JSONs to be mishandled; as a result, logs sometimes showed
  final `collected_response` with `object: chat.completion` but empty `content` (e.g. `"\n"`).
- There was also risk that Docker test containers were using stale or cached images; we
  verified by inspecting the image's `chat_completions.py` that the running container
  contained the updated code after a rebuild.

4. Immediate fixes applied
--------------------------
- Parsing: Rewrote SSE parsing in `chat_completions.py` to:
  - Log raw incoming chunk (debug) as `raw_chunk` (temporarily) to verify provider output.
  - Split chunks by newline, iterate each `data: ` line, ignore comment lines and `[DONE]`.
  - Parse each `data: JSON` entry independently, handle `error` entries, and accumulate
    `choices[0].delta.content` into `collected_response["choices"][0]["message"]["content"]`.
  - Preserve `created`, `id`, `model` if present in any chunk.

- Test tightening: Updated `tests/functional/test_openrouter.py` and `tests/functional/test_gemini.py`
  to assert:
  - Received SSE lines start with `data: ` for JSON events.
  - At least one parsed streaming chunk exists with `object == "chat.completion.chunk"`.
  - A `[DONE]` marker was received.
  - At least one `delta.content` piece contains non-whitespace characters.

- Docker validation: Ensured image contains changes by pulling file from `ai-proxy` image and
  re-running tests after clearing builder cache; observed raw SSE chunks in container logs.

5. Evidence from logs (what provider sends)
------------------------------------------
From a run of the streaming functional test captured in container logs:

: OPENROUTER PROCESSING

data: {"id": "gen-...", "object": "chat.completion.chunk", "choices": [{"delta": {"content": ""}}], ...}

data: {"id": "gen-...", "object": "chat.completion.chunk", "choices": [{"delta": {"content": "1"}}], ...}

data: {"id": "gen-...", "object": "chat.completion.chunk", "choices": [{"delta": {"content": "\n"}}], ...}

data: {"id": "gen-...", "object": "chat.completion.chunk", "choices": [{"delta": {"content": "2"}}], ...}

data: {"id": "gen-...", "object": "chat.completion.chunk", "choices": [{"delta": {"content": "\n"}}], ...}

data: {"id": "gen-...", "object": "chat.completion.chunk", "choices": [{"delta": {"content": "3"}}], ...}

data: {"id": "gen-...", "object": "chat.completion.chunk", "choices": [{"delta": {}, "finish_reason": "stop"}], ...}

data: [DONE]

The provider sends a comment line (starting with `:`), followed by one or more `data:` JSON events
in a single chunk. The content is split across multiple `data` events, sometimes with newline-only
content events; the aggregator needs to concatenate these `delta.content` pieces to reconstruct
the final text (`"1\n2\n3"`).

6. Root causes
---------------
- Incomplete parsing assumptions: the proxy assumed each async chunk contained exactly one
  JSON payload (one `data:` event), but providers can emit multiple `data:` events in a
  single chunk and can include comment/heartbeat lines.
- The tests were insufficiently strict and didn't assert chunk content.
- Logging didn't include raw provider chunks previously, making root-cause analysis harder.

7. Recommendations and next steps (detailed plan)
-----------------------------------------------

7.1 Short-term (next 1-2 days) — stabilize and clean up
- Remove or reduce raw-chunk debug logging in production: make it conditional on
  `LOG_LEVEL == DEBUG` or an environment flag `STREAM_DEBUG=true` to avoid log noise.
- Add unit tests for the SSE parsing and aggregation logic. Create tests which feed an
  async generator that yields complex combinations of SSE payloads, including:
  - multiple `data:` events in one chunk
  - comment lines starting with `:`
  - partial JSON (simulate partial boundaries)
  - `[DONE]` marker
  - error chunks (`{"error": {...}}`)

7.2 Medium-term (1-2 weeks) — refactor and harden
- Refactor parsing/aggregation into a pure function `parse_and_aggregate_sse_chunk(collected_response, chunk)`
  that returns updated `collected_response` and optional `error_response`. This allows easy unit testing
  and removes side-effects from the endpoint handler.
- Create a dedicated module `ai_proxy/utils/sse_parser.py` with:
  - `split_sse_lines(chunk: str) -> List[str]`
  - `parse_sse_data_line(line: str) -> Optional[dict]`
  - `aggregate_parsed_chunk(collected_response, parsed_chunk)`
  - Full unit tests covering many edge cases and provider quirks.

7.3 Long-term (1+ month) — observability & contract testing
- Add contract tests that verify provider SSE semantics periodically (can be nightly):
  - Ensure provider sends `data: { ... }` chunks with `object: chat.completion.chunk` when `stream: true`.
  - Verify that content pieces appear and can be concatenated meaningfully.
- Improve log format to include a short digest of raw chunks (e.g. first 512 bytes hex/trimmed)
  instead of raw long strings to keep logs readable while retaining debugability.
- Integrate synthetic provider simulator for CI: a small fake SSE server that replicates
  provider quirks (comments, multi-line chunks, partial JSON). Run functional tests
  against simulator in CI to catch regressions without calling real APIs.

8. Implementation notes for future devs
-------------------------------------
- When changing streaming logic, always run `make test-functional-openrouter`.
- To debug streaming you can enable `STREAM_DEBUG=true` (if added) or set `LOG_LEVEL=INFO`
  for functional runs; but avoid enabling raw-chunk logs in long-running production builds.
- Keep SSE handling robust: treat each `data: ...` line as a self-contained JSON event and
  ignore non-`data:` lines except to treat `: comment` as heartbeat.

9. Appendix — Code pointers
---------------------------
- Endpoint: `ai_proxy/api/v1/chat_completions.py` (parsing & logging)
- Adapters: `ai_proxy/adapters/openrouter.py`, `ai_proxy/adapters/gemini.py`
- Routing: `ai_proxy/core/routing.py`
- Tests: `tests/functional/test_openrouter.py`, `tests/functional/test_gemini.py`,
  `tests/unit/api/test_chat_core.py`
- Logs: `logs/v1_chat_completions.log`, `logs/models/*.log`

10. Closing
-----------
We turned an ambiguous passing test into a verified streaming path by (a) making the test
actually assert streaming content, (b) adding raw-chunk logging to observe provider output,
and (c) fixing the parser to handle multiple SSE events per chunk and accumulate content
correctly. The suggested follow-ups (refactoring, unit tests, simulator and guarded debug
logging) will make the system more robust and make regressions detectable in CI rather
than manual debugging.

---
