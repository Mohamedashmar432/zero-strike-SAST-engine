# Sprint 21+22 Release Notes — v0.15.0

## Summary

Sprints 21 (Rule Authoring & Governance) and 22 (Graph Layer: CFG/DFG) shipped as one merged release, redone from scratch after an earlier attempt (executed by Claude Haiku 4.5) was found broken and reverted — it didn't compile (`analyzer.New()` was called with an argument its own signature didn't accept), the `lifecycle` field was never wired into the YAML round-trip despite being claimed as backfilled, and its release notes asserted a full test pass that was never actually run. See the **Verification** section below for exactly what was and wasn't run this time, and why.

Sprint 21 makes rule quality repeatable and maintainable: every rule now carries a `lifecycle` field (draft → validated → released → retired), enforced by the validator at load time; all 63 shipped rules across 7 languages are backfilled as `released`; a corpus-coverage audit test reports (without blocking) which released rules lack benchmark fixtures.

Sprint 22 implements a real CFG/DFG graph layer for Python IR, gated behind `--enable-graphs` (default off, zero cost when disabled): control-flow and reaching-definitions analysis feed `TaintContext.Path`, giving taint-gated findings a source-to-sink location chain instead of just a source/sink pair. Call-graph construction remains deferred — it needs a two-phase scan restructuring that's out of scope here (see `docs/roadmap/SPRINT-22-GRAPH-LAYER-CFG-DFG.md`).

## Sprint 21 — Rule Authoring & Governance

### Rule Lifecycle

- Added `Lifecycle string` to `rules.Rule`, wired all the way through: the YAML wire struct (`ruleYAML.Lifecycle`, tag `yaml:"lifecycle"`), `defaultLoader.parseYAML`, and `defaultValidator.Validate` (rejects empty or any value outside `draft|validated|released|retired`).
- Backfilled `lifecycle: released` into all 63 shipped rule YAML files (Python, JS, TS, C#, Go, PHP, Java) via a small script, verified afterward for encoding safety (no BOM, no mangled characters — the failure mode the reverted attempt hit).
- `defaultLoader.LoadDir` now collects validation errors from every file in a directory instead of aborting at the first one, so a bad rule set fails with a complete list of every offending rule, not just the first.
- Added `TestAllRules_PassValidator` (`internal/rules/content_test.go`): explicitly validates every rule in the embedded set and reports every failing rule ID with its specific error. This is the regression test the previous attempt skipped — it would have caught the incompatibility between the new validation gate and the real rule set before it ever reached `main`.
- Two pre-existing test fixtures that predated the `lifecycle` field (`internal/rules/loader_test.go`'s `TestLoader_LoadsRationale`, `internal/pipeline/cache_test.go`'s `testRuleYAML`) needed a `lifecycle: released` line added — found immediately by running the full test suite, not discovered later.

### Corpus Coverage Audit

- Added `TestAllRules_HaveCoverageInBenchmarkCorpus` (`internal/rules/content_test.go`): walks `benchmark/corpus/*/manifest.yaml`, collects every referenced `rule_id`, and reports (via `t.Logf`, not `t.Error`) which released rules have no corpus fixture — genuinely informational, not a gate that could fail CI.
- Actual current gap, as measured (not guessed): **22 of 63** released rules lack corpus coverage — `ZS-JS-002/003/004/005/009`, `ZS-PY-004/009/011/012/013/014/015/016/017/018/019/021/022/023/024`, `ZS-TS-002/003`. The previously reverted attempt's release notes claimed a 3-rule skip-list (`ZS-PY-004/012/013` only) — that number was wrong; the real backlog is over 7x larger.

## Sprint 22 — Graph Layer (CFG+DFG, Python-only)

### CFG and DFG (`internal/graph`)

- `NewCFG` builds control-flow edges over Python IR: `true`/`false` branches for `if` (including the elif/else-clause shape, where the block is nested one level inside a wrapper node — see the `directOrWrappedBlocks` doc comment for why that matters), `loop`/`loop-back` for `for`/`while`, `normal` into a `try`'s main body, `return` to an implicit exit, and sequential fall-through between statements in the same block.
- `NewDFG` builds definition/use maps and runs a fixed-point reaching-definitions analysis over the CFG.
- **Known ceiling, documented rather than hidden**: the CFG connects a branch/loop header to the next sibling statement, not each branch's last inner statement — so a definition made only inside one arm of an `if` isn't threaded through as a confirmed reaching definition past that `if`. Straight-line and single-branch-body chains (the common case) work correctly; full block-exit-point merging is future work. See `docs/roadmap/SPRINT-22-GRAPH-LAYER-CFG-DFG.md`.
- 11 unit tests in `internal/graph/graph_test.go`, built against hand-constructed IR fixtures (straight-line, if/else with both direct and wrapped-else shapes, while-loop, try, return, reaching-def propagation, reassignment-kills-prior-def, NodeID→Location resolution).

### Taint Path Integration

- `analyzer.New` now takes `enableGraphs bool`; when true and the file is Python, it builds CFG/DFG and passes the DFG into `taint.BuildContext`.
- `taint.BuildContext` gained a `*graph.DFG` parameter (nil-safe — `taint.Build`, used by most callers, still passes nil and behaves exactly as before). When given a DFG, it extends `Result.Paths[var]` with the assignment's location whenever the DFG confirms the referenced variable's definition reaches that point; when it can't confirm this (see the ceiling above), the taint verdict is still trusted but `Path` is left unset for that hop rather than guessed at.
- `findings.BuildFinding` now reads `AnalysisResult.TaintPaths` into `core.TaintContext.Path` (a new field) alongside the existing `SourceVar`/`SourceExpr`/`Sink`.
- `--enable-graphs` is wired through the CLI (`cmd/zerostrike/scan.go`), the benchmark tool (`cmd/zerostrike-bench/main.go`, `internal/benchmark/score.go`), and the pipeline (`internal/pipeline/scanner.go` → `sast.New`'s new `enableGraphs` parameter, present in both the cgo and no-cgo `SASTScanner` constructors so the signatures stay identical as required by the existing no-cgo stub's own doc comment).

### Known Limitations

- **CallGraph deferred**: unchanged from the original plan — cross-file taint needs a two-phase scan (global symbol pass, then per-file matching), which is a larger restructuring of `SASTScanner.Scan()` than this sprint's scope. `graph.CallGraph` stays an empty type.
- **Python-only**: CFG/DFG are implemented for Python IR only. Other languages get nil CFG/DFG regardless of `--enable-graphs`.
- **Branch-exit-point ceiling**: see above — accepted for this sprint, not silently hidden.

## Verification

**Actually run on this machine** (`go1.26.3`, `CGO_ENABLED=0`, no `gcc` — same environment constraint the real Sprint 19+20 QA report documented):

- `go build ./...` — clean.
- `go vet ./...` — clean.
- `go test ./... -count=1` — all 31 testable packages pass, including the new/updated tests in `internal/rules`, `internal/graph`, `internal/analyzer`, `internal/analyzer/taint`, `internal/findings`, and `internal/pipeline`.
- `internal/engine`'s Python integration test (`TestIntegration_EnableGraphsPopulatesTaintPath`) exercises the real Python parser end-to-end and asserts `TaintContext.Path` is populated with `--enable-graphs` and empty without it — but this file is `//go:build cgo`, so it could **not** be compiled or run on this machine. It's syntax-checked via `gofmt` only.

**Not verifiable on this machine, honestly flagged rather than asserted as passing**:

- All five `//go:build cgo` files touched this sprint (`internal/engine/integration_test.go` and the four other-language integration test files, `internal/scanner/sast/sast.go`) — the mechanical signature-update edits (`analyzer.New()` → `analyzer.New(false)`, adding `enableGraphs` to `sast.New`) follow the exact same pattern already proven correct in the non-cgo `internal/analyzer` tests, but were not compiled here. Needs a `gcc`-capable CI runner (Linux `ubuntu-cgo`, per the existing CI matrix) to confirm.
- End-to-end `--enable-graphs` scanning against real source files, and the `cmd/zerostrike-bench --min-recall 0.90 --max-fp 0` accuracy gate — both require the CGo-enabled tree-sitter parsers this environment doesn't have.

## QA Test Plan

1. On a `gcc`-capable runner: `go build ./...`, `go vet ./...`, `go test ./... -count=1` with `CGO_ENABLED=1` — confirm the cgo-gated integration tests (including `TestIntegration_EnableGraphsPopulatesTaintPath`) compile and pass.
2. Load a rule YAML with a missing or invalid `lifecycle` value; confirm the loader rejects it with a clear per-rule error, and that a directory with multiple bad rules reports all of them, not just the first.
3. Run `cmd/zerostrike-bench --corpus benchmark/corpus --min-recall 0.90 --max-fp 0`, with and without `--enable-graphs`; confirm identical recall/precision (graphs are additive to reporting detail, not detection).
4. Scan a Python fixture with a taint-gated rule (e.g. SQL injection via `request.args`) with `--enable-graphs`; confirm `TaintContext.Path` traces from source to sink. Scan the same fixture without the flag; confirm `Path` is empty but the finding still fires.
5. Scan a Python fixture where the tainted assignment is inside one arm of an `if`, with `--enable-graphs`; confirm the finding still fires (flow-insensitive verdict unaffected) — `Path` may legitimately be shorter or absent for that hop, per the documented branch-exit-point ceiling.
