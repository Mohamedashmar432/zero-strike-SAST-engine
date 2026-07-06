# Sprint 15+16 Release Notes

## Summary

Sprint 15 (Framework Misconfiguration Detection) and Sprint 16
(Benchmark-Driven Accuracy QA) shipped as one merged sprint, since Sprint
16 is explicitly designed to score everything shipped so far — including
Sprint 15's own output — in one pass. Sprint 15 adds a new `framework`
scanner modality (four config-file misconfiguration checks, config-based
rather than AST-based); Sprint 16 replaces prose QA with a scored
`benchmark/corpus/` and a `zerostrike-bench` CLI/CI gate that computes
TP/FP/FN/precision/recall. Version bumps to **v0.12.0**.

---

## Framework Misconfiguration Detection

New `internal/scanner/framework/` package implementing the existing
`Scanner` interface — pure Go, raw file reads, no tree-sitter/IR, same
shape as `internal/scanner/secrets`. New `FindingKindConfig` +
`ConfigFinding` side-channel struct on `core.Finding` (mirrors
`SecretFinding`/`DependencyFinding`); zero reporter or allowlist changes
were needed since both already treat `Finding.Kind` generically.

### Checks

| Rule | Finding | Match | CWE / OWASP |
|---|---|---|---|
| ZS-CFG-001 | Django DEBUG enabled | `DEBUG=True/1/yes` in an `.env`-style file | CWE-489 / A02:2025 |
| ZS-CFG-002 | Express missing helmet | `express()` + `.listen()` in one file, no `helmet` reference anywhere in it | CWE-693 / A02:2025 |
| ZS-CFG-003 | Permissive CORS | Wildcard origin in a header/config line or a flattened YAML `origin`-like key | CWE-942 / A02:2025 |
| ZS-CFG-004 | Laravel APP_DEBUG enabled | `APP_DEBUG=true` in `.env` | CWE-489 / A02:2025 |

**Pre-flight finding that reshaped scope:** `ZS-PY-017` (Django `DEBUG =
True`, added in an earlier sprint) already catches the *literal Python
source* form of this misconfiguration via the AST rules engine, since
Django settings files are valid Python. ZS-CFG-001 only fires on the
`.env`-driven form (`django-environ`/`python-decouple` style), which the
rules engine cannot see — avoiding a double-counted misconfiguration
across two mechanisms.

**False-positive mitigations:** `.env.local/.dev/.test/.example/.sample/.dist`
suffixes suppress ZS-CFG-001/004 (standard dotenv non-prod convention);
ZS-CFG-004 additionally reads the same file's `APP_ENV` key and suppresses
when it's `local`/`development`/`testing`. ZS-CFG-002 only fires in the
entrypoint file (the one calling `.listen()`), accepting a false negative
(helmet registered in a different file) over noise on router/middleware
modules.

New `--enable-framework-checks` flag (`EnableFrameworkChecks` in
`pipeline.ScanConfig`), same on/off pattern as `--enable-secrets`/`--enable-sca`.

---

## Benchmark-Driven Accuracy QA

New `benchmark/corpus/` — a scored, manifest-labeled fixture corpus
covering Python, JS, TS, C#, Go, PHP (SAST), secrets, SCA (npm + Go), and
the new framework-misconfig checks. Fixtures are copied from `testdata/`
(or freshly written where none existed, e.g. TypeScript had no prior
fixtures) rather than referenced, since `testdata/` may change for
unrelated unit-test reasons. See `benchmark/README.md` for the manifest
schema and a list of documented v1 scope gaps (Python's taint-gated rules
`ZS-PY-004/012/013` excluded pending CGo-verified confirmation; SCA covers
npm/Go only; pip/Maven/Gemfile are Sprint 18 follow-ups).

New `internal/benchmark` package (`manifest.go`, `score.go`, `report.go`)
and `cmd/zerostrike-bench` CLI: runs the full pipeline (all scanners
enabled) against each corpus subdirectory, matches findings against
manifest expectations (by rule ID, or by `(ecosystem, package)` for SCA
findings, which all share `RuleID=ZS-SCA-001`), and reports TP/FP/FN plus
per-language recall, per-rule precision, and per-modality breakdown as
both JSON and Markdown. Exits non-zero if `--min-recall`/`--max-fp`
thresholds are violated.

New CI job `accuracy` (`.github/workflows/ci.yml`), running only on the
`ubuntu-latest` + `CGO_ENABLED=1` leg (no-CGo builds register no
tree-sitter parsers, so SAST recall would show as a spurious 0% on the
other two legs): `go run ./cmd/zerostrike-bench --corpus benchmark/corpus
--min-recall 0.90 --max-fp 0`.

---

## Files Changed

| File | Change |
|---|---|
| `internal/core/finding.go` | `FindingKindConfig`, `ConfigFinding`, `Config` field |
| `internal/findings/builder.go` | `BuildConfigFinding` + `ConfigInput` |
| `internal/scanner/framework/{scanner,configparse,django,express,cors,laravel,doc}.go` + `scanner_test.go` | New package |
| `internal/pipeline/config.go`, `scanner.go` | `EnableFrameworkChecks` wiring |
| `cmd/zerostrike/scan.go` | `--enable-framework-checks` flag |
| `testdata/framework/{django,express,cors,laravel}/*` | New fixtures |
| `internal/findings/allowlist_test.go` | +1 case proving `ZS-CFG-*` suppression works like every other modality |
| `cmd/zerostrike-bench/main.go` | New benchmark CLI |
| `internal/benchmark/{manifest,score,report}.go` + `score_test.go` | New corpus/scoring package |
| `benchmark/corpus/{python,js,ts,csharp,go,php,secrets,sca,framework}/manifest.yaml` + `cases/*` (Go SAST fixtures live under `testdata/` within that subdir, not `cases/`, so `go build ./...` doesn't try to compile them as real packages) | New scored corpus |
| `benchmark/README.md` | New — corpus/manifest authoring guide + documented scope gaps |
| `docs/accuracy/REPORT-v0.12.0.md` + `.json` | New — committed accuracy report (generated locally, no-CGo; CI's `ubuntu-cgo` leg is authoritative) |
| `.github/workflows/ci.yml` | New `accuracy` job (ubuntu-cgo only), new `scan-e2e` step for `testdata/framework` |
| `docs/roadmap/ARCHITECTURE-DECISIONS.md` | #2, #6 marked resolved |
| `docs/roadmap/README.md` | Sprint index/status updated for the 15+16 merge |
| `cmd/zerostrike/main.go` | Version → `v0.12.0` |

---

## Test Results

`CGO_ENABLED=0 go build ./...`, `go vet ./...`, and `go test ./... -count=1`
all pass locally, including the new `internal/scanner/framework` (10
cases: 4 checks × positive/negative + FP-mitigation cases) and
`internal/benchmark` (8 cases covering rule-match/min-count/dependency
scoring and manifest validation) packages.

`go run ./cmd/zerostrike-bench --corpus benchmark/corpus` was run locally
(no CGo): 100% precision (0 false positives across every clean/negative
fixture — no cross-check false-fired), secrets 5/5, framework 4/4, SCA 2/2
(live OSV API correctly flagged `lodash@4.17.20` and
`github.com/dgrijalva/jwt-go@v3.2.0+incompatible` as vulnerable). SAST
recall is 0% in this local run only because no-CGo registers no parsers —
**the CI `accuracy` job's CGo leg is the authoritative recall number**,
same disclosed constraint as Sprints 11–14.

**CGo path not compiled locally** — no `gcc` in this dev environment. All
`ZS-CFG-*` checks were verified end-to-end via a `CGO_ENABLED=0` build of
`zerostrike scan --enable-framework-checks` against `testdata/framework/`
(pure Go, no CGo needed) and fired/stayed-silent exactly as expected. The
SAST-language benchmark corpus cases (Python/JS/TS/C#/Go/PHP) were
verified by direct inspection against each rule's YAML match pattern (and,
for C#/Go/PHP, by reusing fixtures already verified in prior sprints' CI
runs) rather than by a local CGo run.

---

## Known Limitations

- Benchmark corpus v1 scope gaps are tracked in `benchmark/README.md`
  (Python taint-gated rules excluded, pip/Maven/Gemfile SCA not yet
  covered, SCA cases depend on the live OSV API).
- ZS-CFG-002/003 have no "is this actually production" signal the way
  ZS-CFG-001/004 do via `APP_ENV`/filename — residual false-positive risk
  accepted, partially backstopped by the corpus's `--max-fp 0` gate on
  declared true-negative cases.
- Per-language/per-rule accuracy numbers are reported but not individually
  gated yet — only the overall `--min-recall`/`--max-fp` thresholds fail
  the build. Granular gating is a natural Sprint 17+ follow-up once a
  CI-verified baseline exists.
