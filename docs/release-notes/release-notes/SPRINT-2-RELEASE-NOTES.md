 # ZeroStrike SAST Engine — Sprint 2 Release Notes

**Release:** Sprint 2 — Symbol Table + Diagnostics  
**Date:** 2026-06-23  
**Version:** pre-release (no rule engine, no findings output yet)  
**Prepared for:** QA Engineers  

---

## What Sprint 2 Delivers

Sprint 2 builds the two analysis layers that sit between the parser and the (future) rule engine:

- **Symbol Table** (`internal/symboltable`) — scope-aware tracking of all named entities in a source file: functions, classes, variables, and imports. Supports scope-chain resolution (local → parent → global).
- **Analyzer** (`internal/analyzer`) — orchestrates per-file analysis: takes a parsed `IRFile`, runs the symbol builder, and returns an `AnalysisResult` containing the IR tree, symbol table, and diagnostics.
- **Pipeline wired to Analyzer** — `zerostrike scan` now runs the full parse → IR → symbol analysis chain per file instead of stopping at raw IR. The rule matching slot remains a no-op (`_ = analysisResult`) until Sprint 3.

**Findings output is still zero** — the rule engine is Sprint 3. Sprint 2's output is identical to Sprint 1 from a CLI perspective; the work is internal infrastructure.

---

## What Changed Since Sprint 1

| Area | Sprint 1 | Sprint 2 |
|---|---|---|
| `internal/symboltable` | Interface stub only | Full implementation: `symbolTable`, `SymbolBuilder`, scope-chain resolution |
| `internal/analyzer` | Interface + type stubs only | Full implementation: `defaultAnalyzer.Analyze()` wired |
| `internal/pipeline` | Parsed IR, discarded it | Passes IR through analyzer, discards `AnalysisResult` (Sprint 3 hooks it) |
| `internal/graph` | Empty struct stubs | Unchanged — still stubs (Sprint 8) |
| Test count | 64 | **71** (+7 new) |

---

## New Test Packages

### `internal/symboltable` — 5 new tests

| Test | What it checks |
|---|---|
| `TestDefineAndResolve` | Define a symbol and resolve it by name in its scope |
| `TestResolve_Missing` | Resolve returns `(Symbol{}, false)` for undefined names |
| `TestAllSymbols` | Multiple symbols accumulate correctly |
| `TestBuildFromIR` | Builder extracts `SymbolFunction` from a function IR node |
| `TestScopeChain` | Variable defined inside a function scope resolves from that scope |

### `internal/analyzer` — 2 new tests

| Test | What it checks |
|---|---|
| `TestAnalyze_PopulatesResult` | `Analyze` returns `AnalysisResult` with non-nil `IR`, `Symbols`, correct `File` path, empty `Diagnostics` |
| `TestAnalyze_NilIRFile` | `Analyze(nil)` returns empty result without error |

---

## Prerequisites — Environment Setup

Same as Sprint 1. CGO is required for tree-sitter.

### Required Tools

| Tool | Version | Purpose |
|---|---|---|
| Go | 1.21+ | Build and test |
| GCC (MinGW-w64) | any recent | CGO compilation on Windows |

### MinGW-w64 Location (this machine)

```
C:\Users\MohamedAshmar\mingw64\mingw64\bin\gcc.exe
```

### Set Environment Variables

**Git Bash (recommended):**
```bash
export CGO_ENABLED=1
export PATH="/c/Users/MohamedAshmar/mingw64/mingw64/bin:$PATH"
```

Or inline per command:
```bash
CGO_ENABLED=1 PATH="/c/Users/MohamedAshmar/mingw64/mingw64/bin:$PATH" <go command>
```

**PowerShell:**
```powershell
$env:CGO_ENABLED = "1"
$env:PATH = "C:\Users\MohamedAshmar\mingw64\mingw64\bin;" + $env:PATH
```

---

## Step-by-Step QA Test Plan

### Step 1 — Navigate to Project Directory

```bash
cd C:\Users\MohamedAshmar\playground\zero-strike-code-scanner
```

---

### Step 2 — Verify Build Compiles Clean

```bash
CGO_ENABLED=1 PATH="/c/Users/MohamedAshmar/mingw64/mingw64/bin:$PATH" go build ./...
```

**Expected result:**
- No output (silence = success)
- Exit code `0`

---

### Step 3 — Run Static Analysis (go vet)

```bash
CGO_ENABLED=1 PATH="/c/Users/MohamedAshmar/mingw64/mingw64/bin:$PATH" go vet ./...
```

**Expected result:**
- No output
- Exit code `0`

---

### Step 4 — Run All Unit Tests

```bash
CGO_ENABLED=1 PATH="/c/Users/MohamedAshmar/mingw64/mingw64/bin:$PATH" go test ./... -count=1
```

**Expected result:**
```
ok  github.com/zerostrike/scanner/internal/analyzer      ~1s
ok  github.com/zerostrike/scanner/internal/core          ~1s
ok  github.com/zerostrike/scanner/internal/detector      ~1s
ok  github.com/zerostrike/scanner/internal/ir            ~1s
ok  github.com/zerostrike/scanner/internal/parser/python ~1s
ok  github.com/zerostrike/scanner/internal/pipeline      ~1s
ok  github.com/zerostrike/scanner/internal/symboltable   ~1s
ok  github.com/zerostrike/scanner/internal/walker        ~1s
```

**Two new packages now have tests compared to Sprint 1:** `analyzer` and `symboltable`.

Packages marked `[no test files]` remain stubs — expected.

**Failure indicator:** Any line containing `FAIL` is a test failure. Capture the full `-v` output (see Step 5).

---

### Step 5 — Run Verbose Tests (for failure diagnosis)

```bash
CGO_ENABLED=1 PATH="/c/Users/MohamedAshmar/mingw64/mingw64/bin:$PATH" go test ./... -count=1 -v
```

**Expected total: 71 test cases, 0 failures.**

Full expected test case list:

**`internal/analyzer` (2 tests — NEW in Sprint 2)**
```
--- PASS: TestAnalyze_PopulatesResult
--- PASS: TestAnalyze_NilIRFile
```

**`internal/core` (17 tests — unchanged from Sprint 1)**
```
--- PASS: TestLanguage_IsKnown
--- PASS: TestLanguage_IsKnown/python_is_known
--- PASS: TestLanguage_IsKnown/javascript_is_known
--- PASS: TestLanguage_IsKnown/typescript_is_known
--- PASS: TestLanguage_IsKnown/csharp_is_known
--- PASS: TestLanguage_IsKnown/unknown_is_not_known
--- PASS: TestLanguage_String
--- PASS: TestLocation_String
--- PASS: TestLocation_IsZero
--- PASS: TestZeroStrikeError_Error_WithoutCause
--- PASS: TestZeroStrikeError_Error_WithCause
--- PASS: TestZeroStrikeError_Unwrap
--- PASS: TestZeroStrikeError_Unwrap_NilCause
--- PASS: TestSeverity_Values
--- PASS: TestConfidence_Values
--- PASS: TestEvidence_Fields
--- PASS: TestFinding_Construction
```

**`internal/detector` (27 tests — unchanged from Sprint 1)**
```
--- PASS: TestDetect/.py_→_python
--- PASS: TestDetect/.pyw_→_python
--- PASS: TestDetect/.js_→_javascript
--- PASS: TestDetect/.mjs_→_javascript
--- PASS: TestDetect/.cjs_→_javascript
--- PASS: TestDetect/.jsx_→_javascript
--- PASS: TestDetect/.ts_→_typescript
--- PASS: TestDetect/.tsx_→_typescript
--- PASS: TestDetect/.mts_→_typescript
--- PASS: TestDetect/.cts_→_typescript
--- PASS: TestDetect/.cs_→_csharp
--- PASS: TestDetect/.PY_upper_→_python
--- PASS: TestDetect/.JS_upper_→_javascript
--- PASS: TestDetect/.TS_upper_→_typescript
--- PASS: TestDetect/no_ext_no_content_→_unknown
--- PASS: TestDetect/empty_file_→_unknown
--- PASS: TestDetect/shebang_#!/usr/bin/python_→_python
--- PASS: TestDetect/shebang_#!/usr/bin/python3_→_python
--- PASS: TestDetect/shebang_#!/usr/bin/env_python_→_python
--- PASS: TestDetect/shebang_#!/usr/bin/env_python3_→_python
--- PASS: TestDetect/shebang_#!/usr/bin/node_→_javascript
--- PASS: TestDetect/shebang_#!/usr/bin/env_node_→_javascript
--- PASS: TestDetect/shebang_#!/bin/sh_→_unknown
--- PASS: TestDetect/file.py_with_node_shebang_→_python_(ext_wins)
--- PASS: TestDetect/file.js_with_python_shebang_→_javascript_(ext_wins)
--- PASS: TestDetect/shebang_only_no_newline_→_python
--- PASS: TestDetect/unknown_shebang_→_unknown
```

**`internal/ir` (8 tests — unchanged from Sprint 1)**
```
--- PASS: TestWalk_VisitsAllNodes
--- PASS: TestWalk_StopsOnFalse
--- PASS: TestFindByKind
--- PASS: TestFindByText
--- PASS: TestAncestors
--- PASS: TestDescendants
--- PASS: TestFindCalls_Found
--- PASS: TestFindCalls_NotFound
```

**`internal/parser/python` (2 tests — unchanged from Sprint 1)**
```
--- PASS: TestParse_BasicModule
--- PASS: TestIRBuilder_BasicModule
```

**`internal/pipeline` (2 tests — unchanged from Sprint 1)**
```
--- PASS: TestScanPipeline_Python
--- PASS: TestScanPipeline_EmptyDir
```

**`internal/symboltable` (5 tests — NEW in Sprint 2)**
```
--- PASS: TestDefineAndResolve
--- PASS: TestResolve_Missing
--- PASS: TestAllSymbols
--- PASS: TestBuildFromIR
--- PASS: TestScopeChain
```

**`internal/walker` (8 tests — unchanged from Sprint 1)**
```
--- PASS: TestWalk_EmptyDir
--- PASS: TestWalk_FindsFiles
--- PASS: TestWalk_SkipsGitDir
--- PASS: TestWalk_SkipsNodeModules
--- PASS: TestWalk_SkipsBinaryExtension
--- PASS: TestWalk_SkipsLargeFile
--- PASS: TestWalk_RespectsGitignore
--- PASS: TestWalk_SubdirectoryRecursion
```

---

### Step 6 — Test the CLI: Scan Python Fixtures

```bash
CGO_ENABLED=1 PATH="/c/Users/MohamedAshmar/mingw64/mingw64/bin:$PATH" \
  go run ./cmd/zerostrike scan testdata/python
```

**Expected output:**
```
Scanned 4 files, skipped 0, found 0 findings
```

**Expected exit code:** `0`

> Zero findings is expected — the rule engine is Sprint 3. The pipeline now runs the full parse → IR → symbol analysis chain internally, but findings require rules (not yet implemented).

---

### Step 7 — Test the CLI: Scan with JSON Format Flag

```bash
CGO_ENABLED=1 PATH="/c/Users/MohamedAshmar/mingw64/mingw64/bin:$PATH" \
  go run ./cmd/zerostrike scan --format json testdata/python
```

**Expected:** Same as Step 6. JSON report rendering is still a stub (Sprint 4).

---

### Step 8 — Test the CLI: Language Filter Flag

```bash
CGO_ENABLED=1 PATH="/c/Users/MohamedAshmar/mingw64/mingw64/bin:$PATH" \
  go run ./cmd/zerostrike scan --lang python testdata/python
```

**Expected:** `Scanned 4 files, skipped 0, found 0 findings`

---

### Step 9 — Test the CLI: Scan an Empty Directory

```bash
mkdir /tmp/empty_test_dir
CGO_ENABLED=1 PATH="/c/Users/MohamedAshmar/mingw64/mingw64/bin:$PATH" \
  go run ./cmd/zerostrike scan /tmp/empty_test_dir
```

**Expected output:**
```
Scanned 0 files, skipped 0, found 0 findings
```

**Expected exit code:** `0`

---

### Step 10 — Test the CLI: Invalid Path

```bash
CGO_ENABLED=1 PATH="/c/Users/MohamedAshmar/mingw64/mingw64/bin:$PATH" \
  go run ./cmd/zerostrike scan /nonexistent/path 2>&1
echo "Exit: $?"
```

**Expected:** Error message printed, exit code `2`.

---

### Step 11 — Run the Benchmark

```bash
CGO_ENABLED=1 PATH="/c/Users/MohamedAshmar/mingw64/mingw64/bin:$PATH" \
  go run ./cmd/zerostrike benchmark testdata/python
```

**Expected output (values vary per machine):**
```
Iteration 1: ~15-30ms
Iteration 2: ~15-30ms
Iteration 3: ~15-30ms

p50: ~20ms
p95: ~25ms
```

> Sprint 2 adds symbol table construction per file. Expect a small increase (~5-10ms) over Sprint 1's ~15ms on the 4-file fixture set. Any p50 under 500ms for 4 files is passing.

**Also run on the target repository for regression check:**

```bash
CGO_ENABLED=1 PATH="/c/Users/MohamedAshmar/mingw64/mingw64/bin:$PATH" \
  go run ./cmd/zerostrike benchmark "C:\Users\MohamedAshmar\playground\zero-strike-cli"
```

**Expected:** Completes in under 5 seconds p50. Sprint 1 baseline was ~162ms for 150 files.

---

### Step 12 — Test Help Output

```bash
CGO_ENABLED=1 PATH="/c/Users/MohamedAshmar/mingw64/mingw64/bin:$PATH" \
  go run ./cmd/zerostrike --help

CGO_ENABLED=1 PATH="/c/Users/MohamedAshmar/mingw64/mingw64/bin:$PATH" \
  go run ./cmd/zerostrike scan --help

CGO_ENABLED=1 PATH="/c/Users/MohamedAshmar/mingw64/mingw64/bin:$PATH" \
  go run ./cmd/zerostrike benchmark --help
```

**Expected `scan --help` output (unchanged from Sprint 1):**
```
Scan a directory for security vulnerabilities

Usage:
  zerostrike scan <path> [flags]

Flags:
      --enable-graphs   enable CFG/DFG analysis
      --format string   output format: json|sarif|html (default "json")
  -h, --help            help for scan
      --lang strings    languages to scan (default: auto-detect)
      --no-cache        disable file cache
      --output string   output file (default: stdout)
      --rules string    rules directory (default: embedded)
      --workers int     worker count (default: NumCPU)
```

---

### Step 13 (Bonus) — Scan Target Repository

```bash
CGO_ENABLED=1 PATH="/c/Users/MohamedAshmar/mingw64/mingw64/bin:$PATH" \
  go run ./cmd/zerostrike scan "C:\Users\MohamedAshmar\playground\zero-strike-cli"
```

**Expected:**
```
Scanned 150 files, skipped 67, found 0 findings
```

Same file counts as Sprint 1 — skipped files are `.venv`, binaries, and gitignored paths.

---

## Known Limitations in Sprint 2

| Limitation | Expected in Sprint |
|---|---|
| No security findings produced — rule engine not implemented | Sprint 3 |
| JSON/SARIF/HTML output is a stub — report content is minimal | Sprint 4 |
| JavaScript, TypeScript, C# parsers are stubs | Sprint 5 & 6 |
| Symbol table built per file but not yet consumed by rules | Sprint 3 |
| No caching of parsed files between runs | Sprint 7 |
| CFG/DFG graph analysis is a no-op stub | Sprint 8 |
| Taint propagation is a no-op stub | Sprint 8 |

These are **by design** for Sprint 2, not defects.

---

## Exit Code Reference

| Exit Code | Meaning |
|---|---|
| `0` | Scan completed, no findings |
| `1` | Scan completed, findings detected (Sprint 3+) |
| `2` | Scan error (invalid path, parse error, etc.) |

---

## QA Sign-Off Checklist

Copy this checklist into your test report and check off each item:

```
[ ] Step 2  — go build ./...                exits 0, no errors
[ ] Step 3  — go vet ./...                  exits 0, no warnings
[ ] Step 4  — go test ./...                 8 packages PASS, 0 FAIL
[ ] Step 5  — go test -v                    71 test cases all PASS, no FAIL lines
[ ] Step 6  — scan testdata/python          "Scanned 4 files, skipped 0, found 0 findings"
[ ] Step 7  — --format json flag            no crash, output produced
[ ] Step 8  — --lang python flag            no crash, same file count
[ ] Step 9  — empty directory scan          "Scanned 0 files, skipped 0, found 0 findings"
[ ] Step 10 — invalid path                  error message shown, exit code 2
[ ] Step 11 — benchmark testdata/python     p50 value shown, completes under 500ms
[ ] Step 12 — --help output                 all flags listed correctly
[ ] Step 13 — scan zero-strike-cli (bonus)  150 files scanned, 67 skipped, 0 findings
```

**Sprint 2 passes QA when Steps 2–12 are all checked (Step 13 is bonus).**
