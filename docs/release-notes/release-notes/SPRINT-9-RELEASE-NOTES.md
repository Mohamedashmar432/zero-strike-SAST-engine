# Sprint 9 Release Notes

## Summary

Sprint 9 ships three user-facing improvements and a version bump to **v0.6.0**. The HTML reporter completes the output format triangle — `json`, `sarif`, and `html` are all now functional via `--format`. The allowlist path glob engine is upgraded from `filepath.Match` to `doublestar`, adding `**` recursive pattern support so monorepo suppressions like `src/**/*.py` work correctly. The SCA scanner gains Go module support: `go.mod` files are now parsed and their dependencies queried against the OSV advisory database.

---

## New Feature: HTML Reporter

### What it does

`--format html` produces a self-contained HTML page with no external dependencies (no CDN, no JavaScript). The page is safe to open offline or attach to a ticket.

### Page layout

| Section | Content |
|---|---|
| Metadata card | Scan ID, scanner version, root path, start time, duration, branch/commit (when present) |
| Stats grid | Files scanned · Total findings · Suppressed |
| Findings tables | One table per severity level (critical → high → medium → low → info), colour-coded |
| Empty state | "No findings — clean scan." when there are zero results |

### CLI usage

```bash
# Write to a file
zerostrike scan --format html --output report.html ./src

# Pipe to stdout
zerostrike scan --format html ./src > report.html
```

### QA test cases

**TC-9.1 — HTML output is valid and contains scan metadata**

```bash
zerostrike scan --format html --output /tmp/sprint9-report.html .
```

Expected: exit 0 (or 1 if findings exist), `/tmp/sprint9-report.html` created, file starts with `<!DOCTYPE html>`, contains the text `ZeroStrike Scan Report`.

**TC-9.2 — Findings appear in the correct severity section**

Run against a directory with at least one Python file containing `eval(`. Verify the generated HTML contains:
- The rule ID `ZS-PY-001`
- The word `High` (section header)
- The source file path

**TC-9.3 — Clean scan shows empty-state message**

Run against an empty directory (no source files). Verify the HTML contains `clean scan` and no `<table>` elements.

**TC-9.4 — Unsupported format still errors**

```bash
zerostrike scan --format xml . 2>&1
```

Expected: non-zero exit, error message reads `unsupported format "xml" (supported: json, sarif, html)`.

---

## Enhancement: AllowList `**` Glob Support

### Problem

The previous path matcher used `filepath.Match`, which does not support `**`. Suppression entries like `src/**/*.py` silently failed to match any file.

### Fix

Path matching now uses `github.com/bmatcuk/doublestar/v4`. Both base-name matching and full-path matching benefit from `**` support. All existing `filepath.Match` glob patterns continue to work unchanged.

### Supported pattern examples

| Pattern | Matches |
|---|---|
| `*.py` | Any `.py` file in any directory (base-name match) |
| `tests/*` | Files directly inside `tests/` |
| `src/**/*.py` | Any `.py` file anywhere under `src/` |
| `**/fixtures/**` | Any file inside any `fixtures/` directory at any depth |

### QA test cases

**TC-9.5 — `**` glob suppresses nested findings**

Create `.zs-allow.yaml`:
```yaml
version: "1"
suppressions:
  - id: ZS-PY-001
    path: src/**/*.py
    reason: "nested eval test"
```

Run:
```bash
zerostrike scan --allow-file .zs-allow.yaml --format json . | jq '.Findings | length'
```

Expected: findings in `src/` subdirectories for `ZS-PY-001` are suppressed (count reduced compared to without allowlist).

**TC-9.6 — Suppression does not bleed to other paths**

Using the same `.zs-allow.yaml` from TC-9.5, verify that a finding in `other/app.py` for `ZS-PY-001` is **not** suppressed (still appears in output).

**TC-9.7 — Existing single-star patterns still work**

```yaml
suppressions:
  - id: ZS-PY-001
    path: tests/*.py
```

Verify that a finding in `tests/fixtures.py` is suppressed and a finding in `tests/sub/fixtures.py` is **not** suppressed (single `*` does not cross directory boundaries).

---

## New Feature: SCA go.mod Support

### What it does

The SCA scanner now accepts `go.mod` files. Direct and indirect dependencies are extracted and queried against the OSV advisory database. Only `require` directives are parsed; `replace` and `exclude` directives are ignored.

### Dependency classification

| Condition | `Direct` flag |
|---|---|
| No `// indirect` comment | `true` |
| Has `// indirect` comment | `false` |

### Ecosystem identifier

Dependencies from `go.mod` use `"Go"` as the ecosystem string, matching the OSV API's Go ecosystem identifier.

### CLI usage

```bash
zerostrike scan --enable-sca --format json ./mygoproject
```

ZeroStrike will pick up `go.mod` automatically alongside any other supported manifest files in the scanned directory tree.

### QA test cases

**TC-9.8 — go.mod dependencies are discovered**

Create a minimal `go.mod` in a temp directory:
```
module example.com/test

go 1.21

require (
    github.com/sirupsen/logrus v1.9.3
    github.com/spf13/cobra v1.8.0
)
```

Run:
```bash
zerostrike scan --enable-sca --format json /tmp/gomod-test | jq '.Stats.ByScanner'
```

Expected: `"sca"` key present in output (even if no advisories found for those versions).

**TC-9.9 — Indirect deps are included in scan**

Add `github.com/davecgh/go-spew v1.1.1 // indirect` to the `go.mod` from TC-9.8. Re-run. Verify three deps are scanned (count via OSV response or diagnostic output with `--sca-on-error warn`).

**TC-9.10 — go.mod is not picked up without --enable-sca**

```bash
zerostrike scan --format json /tmp/gomod-test | jq '.Stats.ByScanner'
```

Expected: `"sca"` key absent — SCA scanner is disabled by default.

---

## Version Bump

`zerostrike --version` now reports **v0.6.0** (was `v0.5.0-pre`).

```bash
zerostrike --version
# zerostrike version v0.6.0
```

---

## Files Changed

| File | Change |
|---|---|
| `internal/report/html/html.go` | New — full HTML reporter implementation |
| `internal/report/html/html_test.go` | New — 3 tests |
| `cmd/zerostrike/scan.go` | Added `case "html"` to format switch; updated error message; added `htmlreport` import |
| `internal/findings/allowlist.go` | Replaced `filepath.Match` with `doublestar.Match`; removed ponytail ceiling comment; added `doublestar/v4` import |
| `internal/scanner/sca/lockfile.go` | Added `parseGoMod()`, `parseGoModRequireLine()`; extended `parseLockFile()` dispatcher |
| `internal/scanner/sca/scanner.go` | Extended `Accepts()` to match `go.mod` |
| `internal/scanner/sca/lockfile_test.go` | Added `TestParseGoMod` |
| `internal/scanner/sca/testdata/go.mod` | New fixture (2 direct + 1 indirect dep) |
| `cmd/zerostrike/main.go` | Version bumped to `v0.6.0` |
| `go.mod` / `go.sum` | Added `github.com/bmatcuk/doublestar/v4 v4.10.0` |

---

## Test Results

All packages pass. No-CGo build (`CGO_ENABLED=0`) clean across all platforms.

```
ok  internal/analyzer
ok  internal/core
ok  internal/detector
ok  internal/engine
ok  internal/findings         (+2 new: DoubleStarGlob_Match, DoubleStarGlob_NoMatch)
ok  internal/ir
ok  internal/pipeline
ok  internal/report/html      (+3 new: Format, EmptyReport, FindingsRendered)
ok  internal/report/json
ok  internal/report/sarif
ok  internal/rules
ok  internal/scanner/sca      (+1 new: ParseGoMod)
ok  internal/scanner/secrets
ok  internal/symboltable
ok  internal/walker
```

---

## Known Limitations

- TypeScript parser not yet implemented (Sprint 10 candidate).
- SCA does not handle `pom.xml` (Maven) or `Gemfile.lock` (Ruby).
- No CI test coverage gate — coverage is tracked but not enforced.
