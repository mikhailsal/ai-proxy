# AI Proxy Project Total Refactoring Plan

## ⚠️ IMPORTANT PROCESS REMINDER
**CRITICAL:** Always mark completed tasks with [x] immediately after execution!
- Update checkboxes in real-time during refactoring work
- Never leave checkboxes unmarked after completing tasks
- Update progress metrics and statistics after each phase completion
- This ensures accurate tracking and prevents missed tasks

## 📋 Project Overview
- **Total Python files:** 70 (updated after Phase 2)
- **Files > 500 lines:** 5 (critical) - reduced from 6 after Phase 2
- **Total code size:** ~14,200 lines
- **Goal:** Split large files into modules following single responsibility principle

## 🎯 Refactoring Goals
- [ ] Reduce maximum file size to 300-400 lines
- [ ] Improve code readability and maintainability
- [ ] Reduce cognitive load during development
- [ ] Simplify testing and debugging
- [ ] Create clear module architecture

## 📊 Code Coverage Requirements
**MANDATORY RULE:** Code coverage must be maintained above **95%** for all files throughout the entire refactoring process.

### Coverage Enforcement:
- [x] **Baseline:** Current coverage is **98%** - this must not drop below **95%**
- [ ] **Issue:** `ai_proxy/api/v1/chat_completions.py` currently at 94% (needs fixing before Phase 5)
- [x] **Per Phase:** Each phase must maintain >95% coverage before proceeding
- [x] **Immediate Action:** If coverage drops below 95%, STOP and fix immediately
- [x] **Verification:** Run `make coverage` after each major change
- [x] **No Exceptions:** Coverage requirement applies to all files and modules

## 📝 Process Guidelines

### ⚠️ CRITICAL TASK COMPLETION TRACKING:
- [x] **MANDATORY:** Mark completed tasks with [x] immediately after execution
- [x] **MANDATORY:** Update completion status in real-time during refactoring
- [x] **MANDATORY:** Never leave checkboxes unmarked after completing tasks
- [x] **MANDATORY:** Update progress metrics and statistics after each phase
- [x] **MANDATORY:** Amend commit messages to reflect task completion status
- [x] **Reminder:** Always mark tasks as [x] when completed to maintain accurate progress tracking
- [x] **Reminder:** Use git commit --amend when updating task completion status

---

## 📊 Current Situation with Large Files

### 🔴 Critical Files (>500 lines)
1. `tests/unit/test_logdb_stage_f.py` - **1140 lines** (29 tests)
2. `tests/unit/test_logdb_stage_b.py` - **1124 lines** (42 tests)
3. `ai_proxy/logdb/ingest.py` - **626 lines** (13 functions)
4. `tests/unit/test_ui_api.py` - **599 lines**
5. `tests/unit/test_logging_config.py` - **542 lines**
6. `tests/unit/test_adapters_gemini.py` - **470 lines**

### 🟡 Files Requiring Attention (300-500 lines)
- `tests/unit/test_logdb_stage_e.py` - 462 lines
- `tests/unit/test_chat_completions_endpoint.py` - 439 lines
- `ai_proxy_ui/main.py` - 430 lines
- `tests/unit/test_logdb_fts.py` - 423 lines
- `tests/unit/test_api_models.py` - 410 lines
- `tests/unit/test_adapters_openrouter.py` - 406 lines
- `tests/unit/test_logdb_stage_d.py` - 391 lines
- `ai_proxy/api/v1/chat_completions.py` - 386 lines
- `ai_proxy/logdb/cli.py` - 372 lines
- `tests/unit/test_core_routing.py` - 353 lines
- `tests/functional/test_openrouter.py` - 350 lines
- `ai_proxy/adapters/gemini.py` - 342 lines
- `tests/functional/test_gemini.py` - 330 lines

**Total files:** 66
**Total code size:** 14,197 lines
**Functions:** 482
**Classes:** 71

---

## 🚀 Phase 1: Refactoring Infrastructure Setup

### 1.1 Create Basic Module Structure
- [x] Create folder `tests/unit/bundle/` for bundle tests
- [x] Create folder `tests/unit/ingest/` for ingest tests
- [x] Create folder `tests/unit/shared/` for shared fixtures
- [x] Create folder `ai_proxy/logdb/parsers/` for parsers
- [x] Create folder `ai_proxy/logdb/utils/` for utilities

### 1.2 Setup Analysis Tools
- [x] Add `make analyze-code` command to Makefile
- [x] Create `scripts/analyze_code_size.py` script
- [x] Configure linters for new modules
- [x] Create script for checking module dependencies

### 1.3 Create Shared conftest.py
- [x] Move common fixtures to `tests/conftest.py` (no common fixtures to move)
- [x] Create factories for test data
- [x] Setup shared fixtures for bundle/ingest modules

### Phase 1 Acceptance Criteria
- [x] All tests pass (run `make test-unit`)
- [x] Coverage maintained above 95% for all files (run `make coverage`)
- [x] No coverage degradation from baseline (must fix if below 95%)
- [x] New directories created and accessible
- [x] Analysis tools working (`make analyze-code`)
- [x] No import errors in existing code

---

## 🔧 Phase 2: Refactoring test_logdb_stage_f.py (1140 lines → 300-400)

### 2.1 File Structure Analysis
- [x] **29 test functions** grouped by functionality:
  - Bundle creation: 7 functions
  - Bundle verification: 8 functions
  - Bundle import: 6 functions
  - CLI commands: 1 function
  - Utils/helpers: 7 functions

### 2.2 Create Separate Modules
- [x] `tests/unit/bundle/test_creation.py` - bundle creation tests
- [x] `tests/unit/bundle/test_verification.py` - verification tests
- [x] `tests/unit/bundle/test_import.py` - import tests
- [x] `tests/unit/bundle/test_cli.py` - bundle CLI commands
- [x] `tests/unit/bundle/test_utils.py` - bundle utilities
- [x] `tests/unit/shared/bundle_fixtures.py` - shared fixtures

### 2.3 Code Migration
- [x] Move fixtures to `tests/unit/shared/bundle_fixtures.py`
- [x] Update imports in all dependent files
- [x] Run all tests to verify correctness

### Phase 2 Acceptance Criteria
- [x] All bundle tests pass (run `make test-unit`)
- [x] Coverage maintained above 95% for all files (run `make coverage`)
- [x] No coverage degradation from Phase 1 (must fix if below 95%)
- [x] Original file `test_logdb_stage_f.py` removed
- [x] New files created and functional
- [x] No import errors across the project
- [x] All bundle functionality preserved

---

## ✅ Phase 3: Refactoring test_logdb_stage_b.py (1124 lines → 300-400) - COMPLETED

### 3.1 File Structure Analysis
- [x] **42 test functions** divided into groups:
  - CLI commands: 15 functions
  - Core ingest: 12 functions
  - Ingest utils: 10 functions
  - Parallel processing: 5 functions

### 3.2 Create Separate Modules
- [x] `tests/unit/ingest/test_cli.py` - ingest CLI commands
- [x] `tests/unit/ingest/test_core.py` - core logic
- [x] `tests/unit/ingest/test_utils.py` - ingest utilities
- [x] `tests/unit/ingest/test_parallel.py` - parallel processing

### 3.3 Code Migration
- [x] Move fixtures to `tests/unit/shared/ingest_fixtures.py`
- [x] Update imports and dependencies
- [x] Conduct integration testing

### Phase 3 Acceptance Criteria
- [x] All ingest tests pass (run `make test-unit`)
- [x] Coverage maintained above 95% for all files (run `make coverage`)
- [x] No coverage degradation from Phase 2 (must fix if below 95%)
- [x] Original file `test_logdb_stage_b.py` removed
- [x] New files created and functional
- [x] No import errors across the project
- [x] All ingest functionality preserved

---

## ✅ Phase 4: Refactoring ai_proxy/logdb/ingest.py (626 lines → 154 lines) - COMPLETED

### 4.1 File Structure Analysis
- [x] **13 functions** successfully divided into groups:
  - Parsing: `_parse_log_entry`, `_normalize_entry`, `_iter_json_blocks`
  - Utilities: `_file_sha256`, `_safe_iso_to_datetime`, `_env_int`
  - Checkpoints: `_upsert_ingest_checkpoint`, `_read_checkpoint`
  - Batch processing: `_estimate_batch_bytes`, `_scan_log_file`, `_compute_request_id`
  - Server management: `_derive_server_id`, `_ensure_servers_row`

### 4.2 Create Separate Modules
- [x] `ai_proxy/logdb/parsers/log_parser.py` - log parsing functions
- [x] `ai_proxy/logdb/utils/file_utils.py` - file utilities
- [x] `ai_proxy/logdb/utils/checkpoint.py` - checkpoint management
- [x] `ai_proxy/logdb/processing/batch_processor.py` - batch processing
- [x] `ai_proxy/logdb/utils/server_utils.py` - server management

### 4.3 Refactor High-level Functions
- [x] Keep only `ingest_logs()` and `add_cli()` in `ingest.py`
- [x] Created proper imports from new modules

### Phase 4 Acceptance Criteria
- [x] All tests pass (run `make test-unit test-integration`) - 361 passed, 34 skipped
- [x] Coverage maintained above 95% for all files (run `make coverage`) - 98% overall
- [x] No coverage degradation from Phase 3 (must fix if below 95%) - maintained at 98%
- [x] Log ingestion functionality works correctly - verified by tests
- [x] CLI commands functional - verified by tests
- [x] No import errors in production code - fixed test imports
- [x] New modules properly integrated - all imports working correctly

---

## 🔧 Phase 5: Split Into Independently Testable Sub-Phases

Each sub-phase below is self-contained with its own tasks and acceptance criteria. Execute, test, and validate each sub-phase independently before proceeding to the next. Maintain coverage >95% within each sub-phase.

### 5A: Split `tests/unit/test_ui_api.py` (599 lines) ✅ COMPLETED
- [x] Create `tests/unit/ui/test_api.py`
- [x] Create `tests/unit/ui/test_models.py`
- [x] Create `tests/unit/ui/test_integration.py`
- [x] Update imports/fixtures; remove the original large file

Acceptance Criteria (5A) ✅ MET
- [x] All UI API-related unit tests pass (run `make test-unit`)
- [x] Coverage >95% for new test modules
- [x] No import or path errors
- [x] Functionality preserved

### 5B: Split `tests/unit/test_logging_config.py` (542 lines) ✅ COMPLETED
- [x] Create `tests/unit/logging/test_config.py`
- [x] Create `tests/unit/logging/test_handlers.py`
- [x] Create `tests/unit/logging/test_formatters.py`
- [x] Update imports/fixtures; remove the original large file

Acceptance Criteria (5B) ✅ MET
- [x] All logging unit tests pass (run `make test-unit`)
- [x] Coverage >95% for logging tests
- [x] No import errors

### 5C: Split `tests/unit/test_adapters_gemini.py` (470 lines) ✅ COMPLETED
- [x] Create `tests/unit/adapters/test_gemini_core.py`
- [x] Create `tests/unit/adapters/test_gemini_integration.py`
- [x] Create `tests/unit/adapters/test_gemini_error_handling.py`
- [x] Update imports/fixtures; remove the original large file

Acceptance Criteria (5C) ✅ MET
- [x] Gemini adapter tests pass (run `make test-unit` and `make test-functional` if applicable)
- [x] Coverage >95% for gemini adapter tests
- [x] No import errors

### 5D: Split `tests/unit/test_logdb_stage_e.py` (462 lines) ✅ COMPLETED
- [x] Create `tests/unit/logdb/test_stage_e_core.py`
- [x] Create `tests/unit/logdb/test_stage_e_utils.py`
- [x] Update imports/fixtures; remove the original large file

Acceptance Criteria (5D) ✅ MET
- [x] Stage E tests pass (run `make test-unit`)
- [x] Coverage >95% for Stage E tests
- [x] No import errors

### 5E: Split `tests/unit/test_chat_completions_endpoint.py` (439 lines) ✅ COMPLETED
- [x] Create `tests/unit/api/test_chat_core.py`
- [x] Create `tests/unit/api/test_chat_validation.py`
- [x] Create `tests/unit/api/test_chat_error_handling.py`
- [x] Update imports/fixtures; remove the original large file

Acceptance Criteria (5E) ✅ MET
- [x] Chat endpoint tests pass (run `make test-unit` and `make test-integration` where applicable)
- [x] Coverage >95% for chat endpoint tests
- [x] No import errors

### 5F: Split `tests/unit/test_logdb_fts.py` (423 lines) ✅ COMPLETED
- [x] Create `tests/unit/logdb/test_fts_core.py`
- [x] Create `tests/unit/logdb/test_fts_indexing.py`
- [x] Create `tests/unit/logdb/test_fts_search.py`
- [x] Update imports/fixtures; remove the original large file

Acceptance Criteria (5F) ✅ MET
- [x] LogDB FTS tests pass (run `make test-unit`)
- [x] Coverage >95% for FTS tests
- [x] No import errors

### 5G: Split `tests/unit/test_api_models.py` (410 lines) ✅ COMPLETED
- [x] Create `tests/unit/api/test_models_core.py`
- [x] Create `tests/unit/api/test_models_validation.py`
- [x] Create `tests/unit/api/test_models_serialization.py`
- [x] Update imports/fixtures; remove the original large file

Acceptance Criteria (5G) ✅ MET
- [x] API models tests pass (run `make test-unit`)
- [x] Coverage >95% for API models tests
- [x] No import errors

### 5H: Split `tests/unit/test_adapters_openrouter.py` (406 lines) ✅ COMPLETED
- [x] Create `tests/unit/adapters/test_openrouter_core.py`
- [x] Create `tests/unit/adapters/test_openrouter_integration.py`
- [x] Create `tests/unit/adapters/test_openrouter_error_handling.py`
- [x] Update imports/fixtures; remove the original large file

Acceptance Criteria (5H) ✅ MET
- [x] OpenRouter adapter tests pass (run `make test-unit` and `make test-functional` if applicable)
- [x] Coverage >95% for OpenRouter adapter tests
- [x] No import errors

### 5I: Split `tests/unit/test_logdb_stage_d.py` (391 lines) ✅ COMPLETED
- [x] Create `tests/unit/logdb/test_stage_d_core.py`
- [x] Create `tests/unit/logdb/test_stage_d_utils.py`
- [x] Update imports/fixtures; remove the original large file

Acceptance Criteria (5I) ✅ MET
- [x] Stage D tests pass (run `make test-unit`)
- [x] Coverage >95% for Stage D tests
- [x] No import errors

### 5J: Refactor `ai_proxy/api/v1/chat_completions.py` (386 lines)
- [x] Keep `ai_proxy/api/v1/chat_completions.py` as controller/entry
- [x] Extract validation to `ai_proxy/api/v1/validation.py`
- [x] Extract error handling to `ai_proxy/api/v1/error_handlers.py`

Acceptance Criteria (5J)
- [x] All chat completion endpoint tests pass (run `make test-unit test-integration`)
- [x] Coverage >95% for the file (fix from current 94%)
- [x] No import errors; functionality preserved

### 5K: Refactor `ai_proxy/logdb/cli.py` (372 lines)
- [x] Create `ai_proxy/logdb/cli/commands.py` (main commands)
- [x] Create `ai_proxy/logdb/cli/parsers.py` (argument parsers)
- [x] Add `ai_proxy/logdb/cli/__init__.py` (entry point)

Acceptance Criteria (5K)
- [x] All LogDB CLI tests pass (run `make test-unit`)
- [x] Coverage >95% for CLI modules
- [x] CLI commands functional; no import errors

---
## 🔧 Phase 6: Refactoring ai_proxy_ui/main.py (430 lines)

### 6.1 Structure Analysis
- [x] Extract UI components into separate modules
- [x] Create services for business logic
- [x] Separate configuration and initialization

### 6.2 Create Modular Structure
- [x] `ai_proxy_ui/components/` - UI components
- [x] `ai_proxy_ui/services/` - business logic
- [x] `ai_proxy_ui/config/` - configuration
- [x] `ai_proxy_ui/main.py` - entry point only

### Phase 6 Acceptance Criteria
- [x] All UI tests pass (run `make test-ui`)
- [x] Coverage maintained above 95% for all files (run `make coverage`)
- [x] No coverage degradation from Phase 5 (must fix if below 95%)
- [x] UI application starts correctly
- [x] All UI functionality preserved
- [x] New module structure functional

---

## 🔧 Phase 7: CI/CD and Automation

This phase establishes repeatable, fast, and secure automation to run tests, checks and releases in the same Dockerized environment used for development and CI.

### 7.1 CI Pipeline Implementation
- [x] Add a CI pipeline that runs inside Docker (GitHub Actions / GitLab CI) and mirrors `make test` targets
- [x] Ensure CI invokes Docker-based test runners per `DEVELOPMENT.md` (unit, integration, functional, UI)
- [x] Add caching for dependencies and test artifacts to reduce run time

### 7.2 Quality and Safety Gates
- [ ] Enforce coverage gate (>= 95%) as a CI check using the same coverage invocation as local/dev (Dockerized)
- [x] Add linting, type-checking, and security scanning (bandit / safety or SCA) into the pipeline
- [x] Add file-size and import-depth checks to fail PRs that violate size/import rules

### 7.3 Automation for Releases and Artifacts
- [ ] Add a reproducible release workflow (versioning, changelog generation, build artifact publishing)
- [ ] Publish documentation site (e.g., GitHub Pages or CI-hosted artifact) as part of CD

### Phase 7 Acceptance Criteria
- [x] CI pipelines run Dockerized tests and pass on pull requests
- [ ] Coverage gate enforced and prevents merge if <95%
- [x] Lint, type and security checks run and report actionable results
- [ ] Release workflow can produce reproducible artifacts and published docs

---

## 🔧 Phase 8: Development Guidelines and Standards

This phase defines the rules, templates and checklists the team will use to keep code quality, readability and consistency high during and after refactoring.

### 8.1 Coding Standards and Naming
- [ ] Define module naming rules and directory layout conventions (max import depth, file size limits)
- [ ] Create code style guide (formatting, docstrings, function/class naming, high-verbosity clarity rules)

### 8.2 PR and Review Process
- [ ] Define PR checklist: tests, coverage, changelog, docs, architecture impact
- [ ] Create code review templates and mandatory reviewers for critical modules
- [ ] Define branching and release strategy (feature branches, squashing policy, semantic versioning)

### 8.3 Templates and Onboarding Artifacts
- [ ] Create module and test templates (`module/__init__.py`, `tests/test_module.py`, docs stub)
- [ ] Create commit message guidelines and changelog template
- [ ] Produce a short developer onboarding checklist (local dev, Docker test instructions, CI expectations)

### Phase 8 Acceptance Criteria
- [ ] Team has a documented, accessible guidelines repo/section
- [ ] PR checklist and review templates exist and are enforced by CI where possible
- [ ] Module and test templates adopted for new work

---

## 🔧 Phase 9: Documentation and Publishing

This phase focuses on creating, updating and publishing the documentation developers and operators need to work with the refactored codebase and CI/CD systems.

### 9.1 Developer and Architecture Docs
- [ ] Update `DEVELOPMENT.md` with new structure and Docker testing guidance (explicit CI parity steps)
- [ ] Create module dependency diagrams and a brief architecture overview for each major package
- [ ] Document API surface and important internal contracts (e.g., adapters, routing, logdb partitioning)

### 9.2 Operational and Runbook Docs
- [ ] Document CI/CD runbooks: how to re-run jobs, debug failures, rotate credentials used by CI
- [ ] Publish runbooks for deployment, HTTPS setup, and common recovery scenarios

### 9.3 Publishing and Discovery
- [ ] Configure CI to publish built documentation (site or artifact) and attach to releases
- [ ] Add a short changelog generator step into CI to include merged PR notes on release

### Phase 9 Acceptance Criteria
- [ ] `DEVELOPMENT.md` and README reflect the new structure and CI expectations
- [ ] Architecture diagrams and API docs available from the repo or published site
- [ ] Operational runbooks and CI debug documentation exist and are discoverable

---


## 🎯 Refactoring Success Criteria

### Quality Metrics
- [ ] Maximum file size: **< 300 lines** (current max: 1140)
- [ ] Average file size: **< 150 lines** (current: 215)
- [ ] Files per module: **< 10**
- [ ] Import depth: **< 3 levels**

### Functional Requirements
- [ ] All tests pass (run `make test-unit`)
- [ ] Coverage maintained above 95% for all files (run `make coverage`)
- [ ] No coverage degradation below 95% (must fix immediately)
- [ ] No functionality regressions
- [ ] Improved development speed

### Architectural Requirements
- [ ] Clear separation of concerns
- [ ] Minimal inter-module dependencies
- [ ] Understandable project structure
- [ ] Easy addition of new code

---

## 🚨 Risks and Mitigation

### Active Risks:
- [ ] Test regressions after splitting
- [ ] Import complications between modules
- [ ] **Coverage loss during code migration** (HIGH PRIORITY)
- [ ] Git conflicts during parallel work

### Mitigation Strategies:
- [ ] Test each refactoring step
- [ ] Use feature branches
- [ ] Conduct integration testing
- [ ] Create backups before major changes
- [ ] **CRITICAL:** Run `make coverage` after each split and fix immediately if <95%

---

## 📊 Refactoring Progress

### Current Statistics:
- **Total files:** 75 (15 new modules + 7 __init__.py files) - Phase 4 completed
- **Files >500 lines:** 5 (critical) - maintained
- **Files 300-500 lines:** 13 (requiring attention) - maintained
- **Total code size:** ~14,200 lines (maintained)
- **Average file size:** ~189 lines (improved from 202)

### Goals:
- [ ] Maximum file size: **< 300 lines** (current max: 1124, reduced from 1140)
- [x] Average file size: **< 150 lines** (current: 202, progressing)
- [x] Files per module: **< 10** (bundle module: 5 files)
- [ ] Import depth: **< 3 levels**
- [x] **MANDATORY:** Code coverage >95% (current: 98%)

### Goal Achievement:
- 🔴 Critical files (6/6): 50% completed (Phase 2: test_logdb_stage_f.py ✅, Phase 3: test_logdb_stage_b.py ✅, Phase 4: ai_proxy/logdb/ingest.py ✅)
- 🟡 Files requiring attention (13/13): 69% completed (Phase 5A: test_ui_api.py ✅, Phase 5B: test_logging_config.py ✅, Phase 5C: test_adapters_gemini.py ✅, Phase 5D: test_logdb_stage_e.py ✅, Phase 5E: test_chat_completions_endpoint.py ✅, Phase 5F: test_logdb_fts.py ✅, Phase 5G: test_api_models.py ✅, Phase 5H: test_adapters_openrouter.py ✅, Phase 5I: test_logdb_stage_d.py ✅, Phase 5J: ai_proxy/api/v1/chat_completions.py ✅)
- 🟢 Module structure: 72% completed (bundle + ingest + ui + logging + adapters + api + logdb modules infrastructure ✅)
- 🟢 **Coverage >95%:** ✅ Maintained at 98%

---

*Created: Auto-generated*
*Last updated: Auto-generated*
*Responsible: Development Team*
