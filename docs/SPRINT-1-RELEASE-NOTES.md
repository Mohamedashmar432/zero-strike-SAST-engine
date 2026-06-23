# ZeroStrike SAST Engine — Sprint 1 Release Notes

**Release:** Sprint 1 — Foundation  
**Date:** 2026-06-23  
**Version:** pre-release (no rule engine, no findings output yet)  
**Prepared for:** QA Engineers  

---

## What Is ZeroStrike?

ZeroStrike is a proprietary Static Application Security Testing (SAST) engine built in Go. It scans source code repositories for security vulnerabilities without depending on Semgrep, Snyk, Trivy, Gitleaks, or any third-party scanning engine.

---

## What Sprint 1 Delivers

Sprint 1 establishes the full scanning pipeline skeleton. It does **not** produce security findings yet — that is Sprint 3 (Rule Engine). What Sprint 1 proves is:

- The repository can be walked and all source files discovered correctly
- Each file is correctly identified by programming language
- Python source files are parsed into a tree-sitter AST and converted to ZeroStrike's own Intermediate Representation (IR)
- The pipeline orchestrates all of this across a goroutine worker pool
- The CLI (`zerostrike scan`, `zerostrike benchmark`) is wired end-to-end with correct exit codes

---

## Languages Accepted for Scanning

| Language | File Extensions | Detection Method |
|---|---|---|
| **Python** | `.py`, `.pyw` | Extension + shebang fallback |
| **JavaScript** | `.js`, `.mjs`, `.cjs`, `.jsx` | Extension + shebang fallback |
| **TypeScript** | `.ts`, `.tsx`, `.mts`, `.cts` | Extension |
| **C#** | `.cs` | Extension |

**Detection priority:** File extension takes priority over shebang line. If a file has no extension, the first line (`#!/usr/bin/python`, `#!/usr/bin/env node`, etc.) is used.

**Parser status in Sprint 1:**

| Language | Parser Wired | IR Built | Rules Available |
|---|---|---|---|
| Python | YES (tree-sitter) | YES | No (Sprint 3) |
| JavaScript | Stub only | No | No |
| TypeScript | Stub only | No | No |
| C# | Stub only | No | No |

> Python is the only language with a working parser in Sprint 1. JS/TS/C# parsers are stubbed and will be wired in Sprint 5 and 6.

---

## Prerequisites — Environment Setup

Sprint 1 requires **CGO** (C/Go interop) because the tree-sitter parser bindings are C-based.

### Required Tools

| Tool | Version | Purpose |
|---|---|---|
| Go | 1.21+ | Build and test |
| GCC (MinGW-w64) | any recent | CGO compilation on Windows |

### MinGW-w64 Location (this machine)

```
C:\Users\MohamedAshmar\mingw64\mingw64\bin\gcc.exe
```

### Verify GCC is Available

**Git Bash / WSL:**
```bash
/c/Users/MohamedAshmar/mingw64/mingw64/bin/gcc --version
# Expected: gcc (x86_64-posix-seh-rev0, ...) 13.x.x or similar
```

**PowerShell:**
```powershell
& "C:\Users\MohamedAshmar\mingw64\mingw64\bin\gcc.exe" --version
```

---

## Environment Variables for All Commands

Every `go build`, `go test`, and `go run` command **must** be prefixed with these two environment variables. Without them, CGO is disabled and the build fails.

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

**Failure indicator:** Any error message means a build problem. Report the full error output.

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
ok  github.com/zerostrike/scanner/internal/core        ~1s
ok  github.com/zerostrike/scanner/internal/detector    ~1s
ok  github.com/zerostrike/scanner/internal/ir          ~1s
ok  github.com/zerostrike/scanner/internal/parser/python ~1s
ok  github.com/zerostrike/scanner/internal/pipeline    ~1s
ok  github.com/zerostrike/scanner/internal/walker      ~1s
```

Packages marked `[no test files]` are stubs — this is expected for Sprint 1.

**Failure indicator:** Any line containing `FAIL` is a test failure. Capture the full `-v` output (see Step 5).

---

### Step 5 — Run Verbose Tests (for failure diagnosis)

```bash
CGO_ENABLED=1 PATH="/c/Users/MohamedAshmar/mingw64/mingw64/bin:$PATH" go test ./... -count=1 -v
```

**Expected:** Every test case shows `--- PASS`. No `--- FAIL` lines.

Full expected test case list:

**`internal/core` (12 tests)**
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

**`internal/detector` (27 test cases)**
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
--- PASS: TestDetect/.PY_upper_→_python          (case-insensitive check)
--- PASS: TestDetect/.JS_upper_→_javascript      (case-insensitive check)
--- PASS: TestDetect/.TS_upper_→_typescript      (case-insensitive check)
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

**`internal/ir` (8 tests)**
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

**`internal/parser/python` (2 tests)**
```
--- PASS: TestParse_BasicModule      (tree-sitter parses Python source)
--- PASS: TestIRBuilder_BasicModule  (IR tree is built from parse result)
```

**`internal/pipeline` (2 tests)**
```
--- PASS: TestScanPipeline_Python    (scans testdata/python, filesScanned > 0)
--- PASS: TestScanPipeline_EmptyDir  (empty dir returns filesScanned == 0)
```

**`internal/walker` (8 tests)**
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

**Expected exit code:** `0` (no findings — rules are not implemented yet in Sprint 1)

**Check exit code in Bash:**
```bash
echo $?
# Expected: 0
```

---

### Step 7 — Test the CLI: Scan with JSON Format Flag

```bash
CGO_ENABLED=1 PATH="/c/Users/MohamedAshmar/mingw64/mingw64/bin:$PATH" \
  go run ./cmd/zerostrike scan --format json testdata/python
```

**Expected:** Same output as Step 6. JSON report rendering is wired as a stub in Sprint 1 — full JSON output is Sprint 4.

---

### Step 8 — Test the CLI: Language Filter Flag

```bash
CGO_ENABLED=1 PATH="/c/Users/MohamedAshmar/mingw64/mingw64/bin:$PATH" \
  go run ./cmd/zerostrike scan --lang python testdata/python
```

**Expected:** Same result — `Scanned 4 files, skipped 0, found 0 findings`

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

**Expected:** Error message is printed, exit code is `2` (scan error).

---

### Step 11 — Run the Benchmark

```bash
CGO_ENABLED=1 PATH="/c/Users/MohamedAshmar/mingw64/mingw64/bin:$PATH" \
  go run ./cmd/zerostrike benchmark testdata/python
```

**Expected output (values will vary per machine):**
```
Iteration 1: ~15-25ms
Iteration 2: ~15-25ms
Iteration 3: ~15-25ms

p50: ~20ms
p95: ~21ms
min: ~15ms
max: ~25ms
```

**Sprint 1 performance target:** Scanning 4 Python fixture files must complete in well under 15 seconds. Any result under 1 second for this fixture set is passing.

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

**Expected `scan --help` output:**
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

## Known Limitations in Sprint 1

| Limitation | Expected in Sprint |
|---|---|
| No security findings produced — rule engine not implemented | Sprint 3 |
| JSON/SARIF/HTML output is a stub — report content is minimal | Sprint 4 |
| JavaScript, TypeScript, C# parsers are stubs — files are detected but not parsed | Sprint 5 & 6 |
| No caching of parsed files between runs | Sprint 7 |
| CFG/DFG graph analysis behind `--enable-graphs` flag is a no-op stub | Sprint 8 |
| No `.zsignore` support | Sprint 2+ |

These are **by design** for Sprint 1, not defects.

---

## Exit Code Reference

| Exit Code | Meaning |
|---|---|
| `0` | Scan completed, no findings |
| `1` | Scan completed, findings detected (Sprint 3+) |
| `2` | Scan error (invalid path, parse error, etc.) |

---

## Verified Test Results — 2026-06-23

Run on: Windows 11 Pro, Go 1.26.3, MinGW-w64 GCC, AMD64

```
go vet ./...                               PASS  (exit 0, no warnings)

internal/core                              PASS  (17 test cases, 0.349s)
internal/detector                          PASS  (27 test cases, 0.350s)
internal/ir                                PASS  (8 test cases,  0.678s)
internal/parser/python                     PASS  (2 test cases,  0.532s)
internal/pipeline                          PASS  (2 test cases,  0.564s)
internal/walker                            PASS  (8 test cases,  0.372s)

Total: 64 test cases, 0 failures

zerostrike scan testdata/python            Scanned 4 files, skipped 0, found 0 findings
zerostrike benchmark testdata/python       p50: 20ms  p95: 20.7ms  min: 15.2ms
```

---

## QA Sign-Off Checklist

Copy this checklist into your test report and check off each item:

```
[ ] Step 2  — go build ./...             exits 0, no errors
[ ] Step 3  — go vet ./...               exits 0, no warnings
[ ] Step 4  — go test ./...              6 packages PASS, 0 FAIL
[ ] Step 5  — go test -v                 64 test cases all PASS, no FAIL lines
[ ] Step 6  — scan testdata/python       "Scanned 4 files, skipped 0, found 0 findings"
[ ] Step 7  — --format json flag         no crash, output produced
[ ] Step 8  — --lang python flag         no crash, same file count
[ ] Step 9  — empty directory scan       "Scanned 0 files, skipped 0, found 0 findings"
[ ] Step 10 — invalid path               error message shown, exit code 2
[ ] Step 11 — benchmark                  p50 value shown, completes in < 5 seconds
[ ] Step 12 — --help output              all flags listed correctly
```

**Sprint 1 passes QA when all 12 items are checked.**
