# AI Proxy Project Total Refactoring Plan

## 📋 Project Overview
- **Total Python files:** 66
- **Files > 500 lines:** 6 (critical)
- **Total code size:** 14,197 lines
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
- [ ] **Baseline:** Current coverage is **98%** - this must not drop below **95%**
- [ ] **Issue:** `ai_proxy/api/v1/chat_completions.py` currently at 94% (needs fixing before Phase 5)
- [ ] **Per Phase:** Each phase must maintain >95% coverage before proceeding
- [ ] **Immediate Action:** If coverage drops below 95%, STOP and fix immediately
- [ ] **Verification:** Run `make coverage` after each major change
- [ ] **No Exceptions:** Coverage requirement applies to all files and modules

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
- [ ] **29 test functions** grouped by functionality:
  - Bundle creation: 7 functions
  - Bundle verification: 8 functions
  - Bundle import: 6 functions
  - CLI commands: 4 functions
  - Utils/helpers: 4 functions

### 2.2 Create Separate Modules
- [ ] `tests/unit/bundle/test_creation.py` - bundle creation tests
- [ ] `tests/unit/bundle/test_verification.py` - verification tests
- [ ] `tests/unit/bundle/test_import.py` - import tests
- [ ] `tests/unit/bundle/test_cli.py` - bundle CLI commands
- [ ] `tests/unit/bundle/test_utils.py` - bundle utilities

### 2.3 Code Migration
- [ ] Move fixtures to `tests/unit/shared/bundle_fixtures.py`
- [ ] Update imports in all dependent files
- [ ] Run all tests to verify correctness

### Phase 2 Acceptance Criteria
- [ ] All bundle tests pass (run `make test-unit`)
- [ ] Coverage maintained above 95% for all files (run `make coverage`)
- [ ] No coverage degradation from Phase 1 (must fix if below 95%)
- [ ] Original file `test_logdb_stage_f.py` removed
- [ ] New files created and functional
- [ ] No import errors across the project
- [ ] All bundle functionality preserved

---

## 🔧 Phase 3: Refactoring test_logdb_stage_b.py (1124 lines → 300-400)

### 3.1 File Structure Analysis
- [ ] **42 test functions** divided into groups:
  - CLI commands: 15 functions
  - Core ingest: 12 functions
  - Ingest utils: 10 functions
  - Parallel processing: 5 functions

### 3.2 Create Separate Modules
- [ ] `tests/unit/ingest/test_cli.py` - ingest CLI commands
- [ ] `tests/unit/ingest/test_core.py` - core logic
- [ ] `tests/unit/ingest/test_utils.py` - ingest utilities
- [ ] `tests/unit/ingest/test_parallel.py` - parallel processing

### 3.3 Code Migration
- [ ] Move fixtures to `tests/unit/shared/ingest_fixtures.py`
- [ ] Update imports and dependencies
- [ ] Conduct integration testing

### Phase 3 Acceptance Criteria
- [ ] All ingest tests pass (run `make test-unit`)
- [ ] Coverage maintained above 95% for all files (run `make coverage`)
- [ ] No coverage degradation from Phase 2 (must fix if below 95%)
- [ ] Original file `test_logdb_stage_b.py` removed
- [ ] New files created and functional
- [ ] No import errors across the project
- [ ] All ingest functionality preserved

---

## 🔧 Phase 4: Refactoring ai_proxy/logdb/ingest.py (626 lines → 200-300)

### 4.1 File Structure Analysis
- [ ] **13 functions** can be divided into groups:
  - Parsing: `_parse_log_entry`, `_normalize_entry`, `_iter_json_blocks`
  - Utilities: `_file_sha256`, `_safe_iso_to_datetime`, `_env_int`
  - Checkpoints: `_upsert_ingest_checkpoint`, `_read_checkpoint`
  - Batch processing: `_estimate_batch_bytes`, `_scan_log_file`

### 4.2 Create Separate Modules
- [ ] `ai_proxy/logdb/parsers/log_parser.py` - log parsing
- [ ] `ai_proxy/logdb/utils/file_utils.py` - file utilities
- [ ] `ai_proxy/logdb/utils/checkpoint.py` - checkpoint management
- [ ] `ai_proxy/logdb/processing/batch_processor.py` - batch processing

### 4.3 Refactor High-level Functions
- [ ] Keep only `ingest_logs()` and `add_cli()` in `ingest.py`
- [ ] Create facade for accessing low-level functions

### Phase 4 Acceptance Criteria
- [ ] All tests pass (run `make test-unit test-integration`)
- [ ] Coverage maintained above 95% for all files (run `make coverage`)
- [ ] No coverage degradation from Phase 3 (must fix if below 95%)
- [ ] Log ingestion functionality works correctly
- [ ] CLI commands functional
- [ ] No import errors in production code
- [ ] New modules properly integrated

---

## 🔧 Phase 5: Refactoring Remaining Large Files

### 5.1 test_ui_api.py (599 lines)
- [ ] `tests/unit/ui/test_api.py` - UI API tests
- [ ] `tests/unit/ui/test_models.py` - UI model tests
- [ ] `tests/unit/ui/test_integration.py` - integration tests

### 5.2 test_logging_config.py (542 lines)
- [ ] `tests/unit/logging/test_config.py` - basic configuration
- [ ] `tests/unit/logging/test_handlers.py` - log handlers
- [ ] `tests/unit/logging/test_formatters.py` - formatters

### 5.3 test_adapters_gemini.py (470 lines)
- [ ] `tests/unit/adapters/test_gemini_core.py` - core functionality
- [ ] `tests/unit/adapters/test_gemini_integration.py` - integration tests
- [ ] `tests/unit/adapters/test_gemini_error_handling.py` - error handling

### 5.4 test_logdb_stage_e.py (462 lines)
- [ ] `tests/unit/logdb/test_stage_e_core.py`
- [ ] `tests/unit/logdb/test_stage_e_utils.py`

### 5.5 test_chat_completions_endpoint.py (439 lines)
- [ ] `tests/unit/api/test_chat_core.py`
- [ ] `tests/unit/api/test_chat_validation.py`
- [ ] `tests/unit/api/test_chat_error_handling.py`

### 5.6 test_logdb_fts.py (423 lines)
- [ ] `tests/unit/logdb/test_fts_core.py`
- [ ] `tests/unit/logdb/test_fts_indexing.py`
- [ ] `tests/unit/logdb/test_fts_search.py`

### 5.7 test_api_models.py (410 lines)
- [ ] `tests/unit/api/test_models_core.py`
- [ ] `tests/unit/api/test_models_validation.py`
- [ ] `tests/unit/api/test_models_serialization.py`

### 5.8 test_adapters_openrouter.py (406 lines)
- [ ] `tests/unit/adapters/test_openrouter_core.py`
- [ ] `tests/unit/adapters/test_openrouter_integration.py`
- [ ] `tests/unit/adapters/test_openrouter_error_handling.py`

### 5.9 test_logdb_stage_d.py (391 lines)
- [ ] `tests/unit/logdb/test_stage_d_core.py`
- [ ] `tests/unit/logdb/test_stage_d_utils.py`

### 5.10 ai_proxy/api/v1/chat_completions.py (386 lines)
- [ ] `ai_proxy/api/v1/chat_completions.py` (keep)
- [ ] Extract validation to `ai_proxy/api/v1/validation.py`
- [ ] Extract error handling to `ai_proxy/api/v1/error_handlers.py`

### 5.11 ai_proxy/logdb/cli.py (372 lines)
- [ ] `ai_proxy/logdb/cli/commands.py` - main commands
- [ ] `ai_proxy/logdb/cli/parsers.py` - argument parsers
- [ ] `ai_proxy/logdb/cli/__init__.py` - entry point

### 5.12 test_core_routing.py (353 lines)
- [ ] `tests/unit/core/test_routing_core.py`
- [ ] `tests/unit/core/test_routing_validation.py`
- [ ] `tests/unit/core/test_routing_error_handling.py`

### Phase 5 Acceptance Criteria
- [ ] All tests pass (run `make test-unit test-integration`)
- [ ] Coverage maintained above 95% for all files (run `make coverage`)
- [ ] No coverage degradation from Phase 4 (must fix if below 95%)
- [ ] **CRITICAL:** Fix `chat_completions.py` coverage from 94% to >95%
- [ ] All original large files removed
- [ ] New module structure functional
- [ ] No import errors across the project
- [ ] All functionality preserved

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
- **Total files:** 66
- **Files >500 lines:** 6 (critical)
- **Files 300-500 lines:** 13 (requiring attention)
- **Total code size:** 14,197 lines
- **Average file size:** ~215 lines

### Goals:
- [ ] Maximum file size: **< 300 lines** (current max: 1140)
- [ ] Average file size: **< 150 lines** (current: 215)
- [ ] Files per module: **< 10**
- [ ] Import depth: **< 3 levels**
- [ ] **MANDATORY:** Code coverage >95% (current: 98%)

### Goal Achievement:
- 🔴 Critical files (6/6): 0% completed
- 🟡 Files requiring attention (13/13): 0% completed
- 🟢 Module structure: 10% completed (basic infrastructure created)
- 🟢 **Coverage >95%:** ✅ Maintained at 98%

---

*Created: Auto-generated*
*Last updated: Auto-generated*
*Responsible: Development Team*