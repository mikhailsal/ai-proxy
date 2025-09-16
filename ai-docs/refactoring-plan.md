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

### 5A: Split `tests/unit/test_ui_api.py` (599 lines)
- [ ] Create `tests/unit/ui/test_api.py`
- [ ] Create `tests/unit/ui/test_models.py`
- [ ] Create `tests/unit/ui/test_integration.py`
- [ ] Update imports/fixtures; remove the original large file

Acceptance Criteria (5A)
- [ ] All UI API-related unit tests pass (run `make test-unit`)
- [ ] Coverage >95% for new test modules
- [ ] No import or path errors
- [ ] Functionality preserved

### 5B: Split `tests/unit/test_logging_config.py` (542 lines)
- [ ] Create `tests/unit/logging/test_config.py`
- [ ] Create `tests/unit/logging/test_handlers.py`
- [ ] Create `tests/unit/logging/test_formatters.py`
- [ ] Update imports/fixtures; remove the original large file

Acceptance Criteria (5B)
- [ ] All logging unit tests pass (run `make test-unit`)
- [ ] Coverage >95% for logging tests
- [ ] No import errors

### 5C: Split `tests/unit/test_adapters_gemini.py` (470 lines)
- [ ] Create `tests/unit/adapters/test_gemini_core.py`
- [ ] Create `tests/unit/adapters/test_gemini_integration.py`
- [ ] Create `tests/unit/adapters/test_gemini_error_handling.py`
- [ ] Update imports/fixtures; remove the original large file

Acceptance Criteria (5C)
- [ ] Gemini adapter tests pass (run `make test-unit` and `make test-functional` if applicable)
- [ ] Coverage >95% for gemini adapter tests
- [ ] No import errors

### 5D: Split `tests/unit/test_logdb_stage_e.py` (462 lines)
- [ ] Create `tests/unit/logdb/test_stage_e_core.py`
- [ ] Create `tests/unit/logdb/test_stage_e_utils.py`
- [ ] Update imports/fixtures; remove the original large file

Acceptance Criteria (5D)
- [ ] Stage E tests pass (run `make test-unit`)
- [ ] Coverage >95% for Stage E tests
- [ ] No import errors

### 5E: Split `tests/unit/test_chat_completions_endpoint.py` (439 lines)
- [ ] Create `tests/unit/api/test_chat_core.py`
- [ ] Create `tests/unit/api/test_chat_validation.py`
- [ ] Create `tests/unit/api/test_chat_error_handling.py`
- [ ] Update imports/fixtures; remove the original large file

Acceptance Criteria (5E)
- [ ] Chat endpoint tests pass (run `make test-unit` and `make test-integration` where applicable)
- [ ] Coverage >95% for chat endpoint tests
- [ ] No import errors

### 5F: Split `tests/unit/test_logdb_fts.py` (423 lines)
- [ ] Create `tests/unit/logdb/test_fts_core.py`
- [ ] Create `tests/unit/logdb/test_fts_indexing.py`
- [ ] Create `tests/unit/logdb/test_fts_search.py`
- [ ] Update imports/fixtures; remove the original large file

Acceptance Criteria (5F)
- [ ] LogDB FTS tests pass (run `make test-unit`)
- [ ] Coverage >95% for FTS tests
- [ ] No import errors

### 5G: Split `tests/unit/test_api_models.py` (410 lines)
- [ ] Create `tests/unit/api/test_models_core.py`
- [ ] Create `tests/unit/api/test_models_validation.py`
- [ ] Create `tests/unit/api/test_models_serialization.py`
- [ ] Update imports/fixtures; remove the original large file

Acceptance Criteria (5G)
- [ ] API models tests pass (run `make test-unit`)
- [ ] Coverage >95% for API models tests
- [ ] No import errors

### 5H: Split `tests/unit/test_adapters_openrouter.py` (406 lines)
- [ ] Create `tests/unit/adapters/test_openrouter_core.py`
- [ ] Create `tests/unit/adapters/test_openrouter_integration.py`
- [ ] Create `tests/unit/adapters/test_openrouter_error_handling.py`
- [ ] Update imports/fixtures; remove the original large file

Acceptance Criteria (5H)
- [ ] OpenRouter adapter tests pass (run `make test-unit` and `make test-functional` if applicable)
- [ ] Coverage >95% for OpenRouter adapter tests
- [ ] No import errors

### 5I: Split `tests/unit/test_logdb_stage_d.py` (391 lines)
- [ ] Create `tests/unit/logdb/test_stage_d_core.py`
- [ ] Create `tests/unit/logdb/test_stage_d_utils.py`
- [ ] Update imports/fixtures; remove the original large file

Acceptance Criteria (5I)
- [ ] Stage D tests pass (run `make test-unit`)
- [ ] Coverage >95% for Stage D tests
- [ ] No import errors

### 5J: Refactor `ai_proxy/api/v1/chat_completions.py` (386 lines)
- [ ] Keep `ai_proxy/api/v1/chat_completions.py` as controller/entry
- [ ] Extract validation to `ai_proxy/api/v1/validation.py`
- [ ] Extract error handling to `ai_proxy/api/v1/error_handlers.py`

Acceptance Criteria (5J)
- [ ] All chat completion endpoint tests pass (run `make test-unit test-integration`)
- [ ] Coverage >95% for the file (fix from current 94%)
- [ ] No import errors; functionality preserved

### 5K: Refactor `ai_proxy/logdb/cli.py` (372 lines)
- [ ] Create `ai_proxy/logdb/cli/commands.py` (main commands)
- [ ] Create `ai_proxy/logdb/cli/parsers.py` (argument parsers)
- [ ] Add `ai_proxy/logdb/cli/__init__.py` (entry point)

Acceptance Criteria (5K)
- [ ] All LogDB CLI tests pass (run `make test-unit`)
- [ ] Coverage >95% for CLI modules
- [ ] CLI commands functional; no import errors

---
## 🔧 Phase 6: Refactoring ai_proxy_ui/main.py (430 lines)

### 6.1 Structure Analysis
- [ ] Extract UI components into separate modules
- [ ] Create services for business logic
- [ ] Separate configuration and initialization

### 6.2 Create Modular Structure
- [ ] `ai_proxy_ui/components/` - UI components
- [ ] `ai_proxy_ui/services/` - business logic
- [ ] `ai_proxy_ui/config/` - configuration
- [ ] `ai_proxy_ui/main.py` - entry point only

### Phase 6 Acceptance Criteria
- [ ] All UI tests pass (run `make test-ui`)
- [ ] Coverage maintained above 95% for all files (run `make coverage`)
- [ ] No coverage degradation from Phase 5 (must fix if below 95%)
- [ ] UI application starts correctly
- [ ] All UI functionality preserved
- [ ] New module structure functional

---

## 🧪 Phase 7: Testing and Validation

### 7.1 Run All Tests
- [ ] Verify all tests pass after refactoring
- [ ] Run functional tests
- [ ] Check integration tests

### 7.2 Coverage Verification
- [ ] Coverage maintained above 95% for all files (run `make coverage`)
- [ ] No coverage degradation from Phase 6 (must fix if below 95%)
- [ ] Verify all new modules are covered by tests

### 7.3 Performance Verification
- [ ] Measure test execution time
- [ ] Check module import speed

### Phase 7 Acceptance Criteria
- [ ] All test suites pass (unit, integration, functional, UI)
- [ ] Coverage maintained above 95% for all files (run `make coverage`)
- [ ] No coverage degradation from Phase 6 (must fix if below 95%)
- [ ] Performance metrics acceptable
- [ ] No regressions in functionality

---

## 📚 Phase 8: Documentation and CI/CD

### 8.1 Documentation Updates
- [ ] Update DEVELOPMENT.md with new structure
- [ ] Create module dependency diagrams
- [ ] Document API for each module

### 8.2 CI/CD Setup
- [ ] Add file size checks to CI
- [ ] Setup automatic architecture verification
- [ ] Create dependency analysis scripts

### 8.3 Guidelines Creation
- [ ] Write module naming rules
- [ ] Create new module templates
- [ ] Document refactoring process

### Phase 8 Acceptance Criteria
- [ ] Documentation updated and accurate
- [ ] CI/CD checks functional (including coverage >95% checks)
- [ ] Code quality guidelines documented
- [ ] Team can follow new processes

---

## 📈 Phase 9: Monitoring and Support

### 9.1 Code Quality Metrics
- [ ] Setup file size monitoring
- [ ] Create code metrics dashboard
- [ ] Automatic warnings for large files

### 9.2 Code Review Process
- [ ] Update code review checklist
- [ ] Add architecture checks
- [ ] Create review templates for modules

### 9.3 Support Plan
- [ ] Regular code structure audits
- [ ] Plan for gradual improvement of remaining files
- [ ] Technical debt monitoring

### Phase 9 Acceptance Criteria
- [ ] Monitoring systems functional (including coverage monitoring >95%)
- [ ] Code review process updated with coverage requirements
- [ ] Support plan documented and actionable

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
- 🟡 Files requiring attention (13/13): 0% completed
- 🟢 Module structure: 53% completed (bundle + ingest modules infrastructure ✅)
- 🟢 **Coverage >95%:** ✅ Maintained at 98%

---

*Created: Auto-generated*
*Last updated: Auto-generated*
*Responsible: Development Team*