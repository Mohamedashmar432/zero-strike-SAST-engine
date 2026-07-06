# Sprint 7 Release Notes

## Summary

Sprint 7 delivers two production-readiness improvements. The SCA scanner now recognises four additional manifest formats — `yarn.lock`, `pnpm-lock.yaml`, and `Pipfile.lock` — alongside the existing npm and pip support, giving ZeroStrike coverage across the most common JavaScript and Python dependency managers. The pipeline concurrency model is also corrected: the `--workers` flag previously had no effect; scanners now run concurrently when `--workers` is greater than 1.

---

## New Feature: SCA Manifest Expansion

### Supported manifest files (Sprint 7)

| File | Ecosystem | Format |
|------|-----------|--------|
| `package-lock.json` | npm | JSON (v1/v2/v3) — existing |
| `requirements*.txt` | PyPI | Plain text — existing |
| `yarn.lock` | npm | Custom text (v1 classic + v2 Berry) — **new** |
| `pnpm-lock.yaml` | npm | YAML (v6 and v9) — **new** |
| `Pipfile.lock` | PyPI | JSON — **new** |

### Behaviour

- `yarn.lock` (v1): block headers (`package@^version:`) and `version "x.y.z"` lines are parsed into `Dependency` structs with `Ecosystem: "npm"`.
- `yarn.lock` (v2/Berry): same parser handles `version: x.y.z` (no quotes) lines automatically.
- `pnpm-lock.yaml`: the `packages:` map keys (`/package@version` in v6, `package@version` in v9) are split on the last `@`. Scoped packages (`@scope/name`) are handled correctly.
- `Pipfile.lock`: `default` entries are marked `Direct: true`; `develop` entries are marked `Direct: false`. Version strings with the `==` prefix are stripped.

All new dependencies are passed to the existing OSV query pipeline — no changes to advisory lookup or severity mapping.

### SCA Accepts() — updated pattern

```
package-lock.json | yarn.lock | pnpm-lock.yaml | Pipfile.lock | requirements*.txt
```

---

## Enhancement: Pipeline Bounded Fan-out

### Problem

`--workers` (default: `NumCPU`) was stored in `ScanConfig.WorkerCount` but never read inside `pipeline.Run()`. All scanners ran sequentially regardless of the flag.

### Fix

`Run()` now branches on `WorkerCount`:

- `WorkerCount == 1`: existing sequential path (no change in behaviour or output ordering).
- `WorkerCount == 0` or `> 1`: scanners run in parallel goroutines. Each scanner gets its own goroutine; results are collected through a buffered channel. The first scanner error short-circuits and is returned to the caller.

Since ZeroStrike currently has at most three scanners (SAST, Secrets, SCA), the maximum number of concurrent goroutines in this path is three — no semaphore required.

### Default behaviour change

`--workers 0` (the default, meaning `NumCPU`) now enables concurrent execution on multi-core hosts. To opt back into sequential execution explicitly, pass `--workers 1`.

---

## Files Changed

| File | Change |
|------|--------|
| `internal/scanner/sca/lockfile.go` | Added `parseYarnLock()`, `extractYarnPkgName()`, `parsePnpmLock()`, `parsePipfileLock()`; extended `parseLockFile()` dispatcher; added `gopkg.in/yaml.v3` import |
| `internal/scanner/sca/scanner.go` | Extended `Accepts()` to match `yarn.lock`, `pnpm-lock.yaml`, `Pipfile.lock` |
| `internal/scanner/sca/lockfile_test.go` | Added `TestParseYarnLock`, `TestParsePnpmLock`, `TestParsePipfileLock`; added `os`/`path/filepath` imports |
| `internal/scanner/sca/testdata/yarn.lock` | New fixture (2 deps, v1 format) |
| `internal/scanner/sca/testdata/pnpm-lock.yaml` | New fixture (2 deps, v6 format) |
| `internal/scanner/sca/testdata/Pipfile.lock` | New fixture (2 default + 1 develop dep) |
| `internal/pipeline/scanner.go` | Added `runtime` import; concurrent fan-out branch in `Run()` via buffered channel |
| `internal/pipeline/scanner_integration_test.go` | Added `TestScanPipeline_Workers_ConcurrentMatchesSequential` |

---

## Test Results

All non-CGo packages pass (57 tests, +3 from this sprint):

```
ok  github.com/zerostrike/scanner/internal/findings
ok  github.com/zerostrike/scanner/internal/rules
ok  github.com/zerostrike/scanner/internal/core
ok  github.com/zerostrike/scanner/internal/walker
ok  github.com/zerostrike/scanner/internal/symboltable
ok  github.com/zerostrike/scanner/internal/ir
ok  github.com/zerostrike/scanner/internal/analyzer
ok  github.com/zerostrike/scanner/internal/detector
ok  github.com/zerostrike/scanner/internal/scanner/secrets
ok  github.com/zerostrike/scanner/internal/scanner/sca   (+3 new parser tests)
```

CGo-dependent packages (parser/python, parser/javascript, scanner/sast, pipeline) require gcc and cannot be built on this Windows host. The new pipeline integration test `TestScanPipeline_Workers_ConcurrentMatchesSequential` will run in CI.

---

## Known Limitations

- `AllowList` path matching uses `filepath.Match` only — `**` glob is not supported.
- SCA does not yet handle `go.mod`, `Pipfile` (non-lock), `yarn.lock` v3, `pom.xml`, or `gradle.lockfile`.
- TypeScript and C# parsers remain stubs (blocked by CGo/Windows gcc).
