# QA Test Report — Sprint 8

**Date:** 2026-06-24  
**Tester:** senior-qa  
**Engine:** `zero-strike-SAST-engine` (v0.5.0-pre)  
**Targets:** dvna (Node.js) + dvpwa (Python)  
**Scope:** Sprint 7 + Sprint 8 changes

---

## 1. Sprint 7 — SCA Manifest Expansion

**Goal:** Recognise four additional dependency manifest formats.

| Format | Lockfile | Test | Status |
|--------|----------|------|--------|
| npm (package-lock.json v1/v2) | was existing | `TestParsePackageLockJSON_V1`, `V2` | ✅ PASS |
| yarn (yarn.lock) | `testdata/yarn.lock` | `TestParseYarnLock` | ✅ PASS |
| pnpm (pnpm-lock.yaml) | **MISSING** `testdata/pnpm-lock.yaml` | `TestParsePnpmLock` | ❌ **FAIL** |
| pipenv (Pipfile.lock) | `testdata/Pipfile.lock` | `TestParsePipfileLock` | ✅ PASS |

**Result:** 3/4 new formats work. **Bug #1:** `pnpm-lock.yaml` test fixture file was not committed — `TestParsePnpmLock` crashes with `file not found`.

---

## 2. Sprint 8 — Linux CI (GitHub Actions)

**Workflow:** `.github/workflows/ci.yml` — 46 lines

**Matrix:**

| OS | CGo | Job Name | Purpose |
|----|-----|----------|---------|
| ubuntu-latest | 1 | ubuntu (CGo) | Full SAST + CGo-dependent tests |
| ubuntu-latest | 0 | ubuntu (no CGo) | Non-CGo tests on Linux |
| windows-latest | 0 | windows (no CGo) | Non-CGo tests on Windows |

**Jobs:**
- `lint` — runs `go vet ./...`
- `test` — runs `go test ./... -count=1` across the 3-matrix

**Validation:** ✅ YAML is syntactically correct, uses `actions/checkout@v4` and `actions/setup-go@v5` with Go module caching.

**Added Makefile target:** `make test-nocgo` — `CGO_ENABLED=0 go test ./... -count=1`

### Actual CI Run Results

All three matrix jobs **FAIL** with the same error:

```
--- FAIL: TestParsePnpmLock (0.00s)
    lockfile_test.go:133: open testdata/pnpm-lock.yaml: no such file or directory
FAIL
FAIL	github.com/zerostrike/scanner/internal/scanner/sca
```

| Job | Result | Details |
|-----|--------|---------|
| **ubuntu (CGo)** | ❌ FAIL | 24 packages pass, 1 fails: `sca` |
| **ubuntu (no CGo)** | ❌ FAIL | 24 packages pass, 1 fails: `sca` |
| **windows (no CGo)** | ❌ FAIL | 24 packages pass, 1 fails: `sca` |

**Key observations from the CGo run:**
- Tree-sitter CGo parser tests **pass** on Linux: `internal/parser/python` ✓, `internal/pipeline` ✓
- All SARIF, JSON, secrets, walker, symboltable tests pass
- The single failure is **identical** across all platforms — the missing `pnpm-lock.yaml` test fixture

**CI is broken** — the workflow runs but `go test ./...` returns exit code 1 on every matrix entry.

---

## 3. Sprint 8 — SARIF Output Format

**New package:** `internal/report/sarif/` — 161 lines

**Tests:** 4 tests — `TestSARIF_Format`, `TestSARIF_Render`, `TestSARIF_SeverityLevels`, `TestSARIF_EmptyFindings`

**Integration:**
- ✅ `zerostrike scan <path> -f sarif` produces valid SARIF 2.1.0 JSON
- ✅ severity mapping: Critical/High → `error`, Medium → `warning`, Low/Info → `note`
- ✅ GitHub Code Scanning ready (URI base `%SRCROOT%`, relative paths)

---

## 4. Sprint 8 — Concurrent Scanner Pipeline

**Change:** `internal/pipeline/scanner.go` — goroutine-based concurrent scanner execution

- ✅ Sequential mode when workers ≤ 1 or ≤ 1 scanner
- ✅ Concurrent mode (goroutine per scanner) when workers > 1
- ✅ `--workers 2` flag accepted and functions
- ✅ Thread-safe result collection via channel

---

## 5. Unit Tests

**Run:** `CGO_ENABLED=0 go test ./... -count=1`

| Package | Tests | Status |
|---------|-------|--------|
| `internal/analyzer` | 2 | ✅ |
| `internal/core` | 17 | ✅ |
| `internal/detector` | 27 (sub-cases) | ✅ |
| `internal/engine` | 4 | ✅ |
| `internal/findings` | 9 | ✅ |
| `internal/ir` | 8 | ✅ |
| `internal/pipeline` | 6 (arch) | ✅ |
| `internal/report/json` | 3 | ✅ |
| `internal/report/sarif` | 4 | ✅ |
| `internal/rules` | 12 | ✅ |
| `internal/scanner/secrets` | 10 | ✅ |
| `internal/scanner/sca` | 10 | ❌ **1 FAIL** |
| `internal/symboltable` | 9 | ✅ |
| `internal/walker` | 8 | ✅ |

**Total:** 93 passed, **1 failed** — `TestParsePnpmLock` (missing testdata)

---

## 6. End-to-End Scan Results

### dvna (Node.js — vulnerable app)

| Scanner | Findings | Notes |
|---------|----------|-------|
| SAST | 0 | No CGo on Windows — tree-sitter parsers unavailable |
| Secrets | 0 | No hardcoded secrets detected |
| SCA | N/A | No `--enable-sca` run for this target |

### dvpwa (Python — vulnerable app)

| Scanner | Findings | Notes |
|---------|----------|-------|
| SAST | 0 | No CGo on Windows — tree-sitter parsers unavailable |
| Secrets | 0 | No hardcoded secrets detected |
| SCA | **1** | `aiohttp 3.5.3` vulnerable — CVE-2026-54279 (GHSA-2fqr-mr3j-6wp8) |

**SCA finding detail:**
- Package: `aiohttp` (PyPI)
- Installed: `3.5.3`, Fixed in: `>=3.14.1`
- Severity: Low / Low (OSV-based advisory)
- Manifest: `requirements.txt`

**Note:** SAST findings require CGo (Linux CI or MinGW-w64 on Windows). This is documented behaviour — the Linux CI matrix (ubuntu + CGO_ENABLED=1) covers this.

---

## 7. Bugs Found

### Bug #1 — Missing pnpm-lock.yaml Test Fixture

- **File:** `internal/scanner/sca/lockfile_test.go:130-152`
- **Symptom:** `TestParsePnpmLock` fails with `open testdata\pnpm-lock.yaml: file not found`
- **Root cause:** Sprint 7 commit `379aedb` added the test but did not commit the `testdata/pnpm-lock.yaml` file
- **Impact:** Pipeline test suite fails on `go test ./...`
- **Severity:** High (blocks CI `make test` / `make test-nocgo`)

### Bug #2 — HTML Format Flag Not Wired

- **File:** `cmd/zerostrike/scan.go:126-131`
- **Symptom:** `--format html` silently falls back to JSON output
- **Root cause:** The format switch at line 126 only handles `sarif` and `json` (default); the `html` case is missing and HTML reporter package is not imported
- **Impact:** Users requesting HTML output receive JSON instead (silent fallback)
- **Severity:** Medium

### Bug #3 — Hardcoded Scanner Version

- **File:** `cmd/zerostrike/scan.go:115`
- **Symptom:** Scanner version hardcoded as `"v0.5.0-pre"` instead of using build-time ldflags
- **Root cause:** No `-ldflags` injection; version is a string literal
- **Impact:** Version stays `v0.5.0-pre` regardless of actual build tag
- **Severity:** Low

---

## 8. CI Workflow Validation

**Workflow file:** `.github/workflows/ci.yml`

```
name: CI
on: [push, pull_request] → main
jobs:
  lint:
    runs-on: ubuntu-latest
    steps: checkout@v4 → setup-go@v5 → go vet ./...
  test (3-matrix):
    - ubuntu-latest (CGO_ENABLED=1)  → full SAST + CGo tests
    - ubuntu-latest (CGO_ENABLED=0)  → non-CGo tests
    - windows-latest (CGO_ENABLED=0) → non-CGo tests
```

**Recommendations:**
1. Add a `go build ./cmd/zerostrike/` step to the lint job to catch compilation errors early
2. Pin `actions/checkout` and `actions/setup-go` to SHA digests for supply-chain security
3. Add workflow_dispatch trigger for manual CI runs

---

## 9. Summary

| Area | Status |
|------|--------|
| **Sprint 7:** SCA manifest expansion | ⚠️ 3/4 formats work (pnpm-lock missing) |
| **Sprint 8:** Linux CI (GitHub Actions) | ❌ All 3 matrix jobs FAIL (Bug #1) |
| **Sprint 8:** SARIF output | ✅ 4 tests, valid 2.1.0 schema |
| **Sprint 8:** Concurrent pipeline | ✅ Workers flag, goroutine-based |
| **Unit tests (non-CGo)** | ❌ 1 failure (Bug #1) |
| **Unit tests (CGo on Linux)** | ❌ 1 failure (Bug #1) — parser/pipeline CGo tests pass |
| **SAST (Windows, no CGo)** | ⚠️ Stub — requires Linux CI |
| **Secrets scanner** | ✅ 10 tests pass, 0 false positives |
| **SCA scanner (live)** | ✅ 1 real vuln found in dvpwa |
| **HTML format** | ❌ Silent fallback to JSON (Bug #2) |

**Overall Verdict:** 🔴 **CI BROKEN** — Bug #1 (missing `pnpm-lock.yaml`) causes all 3 CI matrix jobs to fail. The workflow runs but `go test ./...` exits non-zero on every OS/CGo combination. Fix the missing test fixture, then re-run. Bug #2 (HTML fallback) is a usability concern but not a blocker.
