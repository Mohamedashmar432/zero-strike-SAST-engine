# Sprint 6 Release Notes

## Summary

Sprint 6 adds a declarative YAML-based allowlist so teams can suppress known-safe findings instead of treating every pattern match as a triage item. The companion change retires ZS-PY-006, a rule that was kept only until suppression was available.

---

## New Feature: Allowlist / Finding Suppression

### How to use

Create `.zs-allow.yaml` at the project root (auto-discovered) or pass `--allow-file <path>`:

```yaml
version: "1"
suppressions:
  # Suppress an entire rule across the project
  - id: ZS-SEC-003
    reason: "All generic API keys here are non-prod test values"

  # Suppress one specific finding instance by stable fingerprint
  - fingerprint: "a3f1b2c4d5e6f7a8"
    reason: "FP: public CI fixture key — not a real credential"

  # Suppress a rule only in a specific directory
  - id: ZS-SEC-004
    path: "tests/*"
    reason: "Hardcoded passwords in test fixtures are expected"
```

The `reason` field is documentation-only and has no effect on matching.

### Matching precedence

1. `fingerprint` set → exact fingerprint match (rule ID and path ignored).
2. `id` + `path` set → rule ID match AND file path match via `filepath.Match`.
3. `id` only → all findings with that rule ID.

> **Note:** `path` uses stdlib `filepath.Match`. The `**` glob pattern is not supported; use `tests/*` not `tests/**`.

### Suppressed count in output

`ScanStats.Suppressed` is populated with the number of filtered findings. This appears in the JSON report under `stats.suppressed`.

### CLI flag

```
--allow-file string   path to allowlist YAML (default: <root>/.zs-allow.yaml)
```

---

## Retired Rule: ZS-PY-006

**ZS-PY-006** (`exec`/`eval`/`os.system` with LHS constraint) has been removed from the embedded rule set. This rule produced a high false-positive rate on test helpers and was held pending the allowlist feature. Teams that needed it suppressed can now use the allowlist for any replacement rule that covers the same pattern.

---

## Files Changed

| File | Change |
|------|--------|
| `internal/findings/allowlist.go` | New — `AllowList`, `LoadAllowList`, `Suppressed()` |
| `internal/findings/allowlist_test.go` | New — 6 unit tests |
| `internal/pipeline/config.go` | Added `AllowFile string` to `ScanConfig` |
| `internal/pipeline/scanner.go` | Load allowlist in `New()`; apply filter in `Run()`; populate `ScanResult.Suppressed` |
| `internal/report/report.go` | Added `Suppressed int` to `ScanStats` |
| `cmd/zerostrike/scan.go` | Added `--allow-file` flag; wire `Suppressed` into stats |
| `internal/rules/data/python/ZS-PY-006.yaml` | Deleted (rule retired) |
| `internal/rules/loader_javascript_test.go` | Removed `TestLoader_ZS_PY_006_LHSIdentifier` |
| `internal/rules/loader_test.go` | Updated Python rule count from 10 → 9 |

---

## Test Results

All non-CGo packages pass (54 tests, +6 from this sprint):

```
ok  github.com/zerostrike/scanner/internal/findings   (6 new allowlist tests)
ok  github.com/zerostrike/scanner/internal/rules
ok  github.com/zerostrike/scanner/internal/core
ok  github.com/zerostrike/scanner/internal/walker
ok  github.com/zerostrike/scanner/internal/symboltable
ok  github.com/zerostrike/scanner/internal/ir
ok  github.com/zerostrike/scanner/internal/analyzer
ok  github.com/zerostrike/scanner/internal/detector
ok  github.com/zerostrike/scanner/internal/scanner/secrets
ok  github.com/zerostrike/scanner/internal/scanner/sca
```

CGo-dependent packages (parser/python, parser/javascript, scanner/sast, pipeline) require gcc and cannot be built on this Windows host.
