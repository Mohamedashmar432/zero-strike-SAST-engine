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

- `NewCFG` builds control-flow edges over Python IR: `true`/`false` branches for `if` (including the elif/else-clause shape, where the block is nested one level inside a wrapper node — see the `directOrWrappedBlocks` doc comment for why that matters), `loop`/`loop-back` for `for`/`while`, `normal` into a `try`'s main body, `return` to an implicit exit, and sequential fall-through between statements in the same block (via `flattenStatements`, which unwraps each line's `simple_statements` container — see **Bug found and fixed** below).
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

## Bug found and fixed after CGO verification became available

The first version of this release note said the cgo-gated integration tests were "not verifiable on this machine" — that was true when written, but an existing MinGW-w64 `gcc` install was subsequently found on the machine (just not on `PATH`), which made a real `CGO_ENABLED=1` build and test run possible. Running it immediately surfaced a real, reproducible failure:

```
--- FAIL: TestIntegration_EnableGraphsPopulatesTaintPath (0.00s)
    integration_test.go:161: expected TaintContext.Path to be populated with --enable-graphs
FAIL    github.com/zerostrike/scanner/internal/engine  0.991s
```

**Root cause**: the real tree-sitter Python grammar wraps every top-level statement line in its own `simple_statements` node, which `internal/graph`'s `mapKind`-driven IR maps to `NodeKindUnknown` (no dedicated kind) — confirmed by dumping the actual IR tree for `user_id = request.args.get('id')\nquery = "SELECT " + user_id`: the two `Assignment` nodes are **grandchildren** of `Module`, not direct children. `NewCFG`'s sequential fall-through pass only connected direct `Module`/`Block` children, so it never linked the two statements — the DFG's reaching-definitions analysis had no CFG edge to propagate across, `taint.extendPath` correctly (per its own contract) refused to assert an unconfirmed path, and `TaintContext.Path` stayed empty even for this straight-line case, which was supposed to be the one scenario this sprint's CFG guaranteed.

**Fix**: `internal/graph/graph.go` gained `flattenStatements`, which unwraps `NodeKindUnknown` containers (recursively, since it's the same generic "unrecognized grammar node" bucket) to find the real statement nodes before building fall-through edges — mirroring the wrapper-transparency `directOrWrappedBlocks` already had for elif/else clauses, just applied to the statement-sequencing pass too, which had been missed.

This is a genuine, hand-built-IR-test blind spot: `internal/graph/graph_test.go`'s fixtures construct `Module`/`Block` nodes with statements as *direct* children (a reasonable simplification for testing CFG/DFG algorithms in isolation), so they never exercised the real grammar's wrapping shape — only the cgo-gated integration test, running against the actual parser, could catch this. All 11 hand-built-IR unit tests still pass after the fix (they didn't need to change), and it's now additionally verified against the real parser.

## Verification

**Actually run, with real `CGO_ENABLED=1` and MinGW-w64 gcc** (not just non-cgo, as originally reported):

- `go build ./...` — clean, both `CGO_ENABLED=0` and `CGO_ENABLED=1`.
- `go vet ./...` — clean under both.
- `go test ./... -count=1` under `CGO_ENABLED=1` — **all 31 packages pass**, including every `//go:build cgo` file touched this sprint (`internal/engine`'s five integration test files, `internal/scanner/sast/sast.go`) and the fixed `TestIntegration_EnableGraphsPopulatesTaintPath`.
- `cmd/zerostrike-bench --corpus benchmark/corpus --min-recall 0.90 --max-fp 0`, built and run with real CGO: **TP=53 FP=0 FN=0, precision=100.00%, recall=100.00%**, identical with and without `--enable-graphs` — confirms graphs are additive to reporting detail only, not detection, exactly as claimed.

Nothing in this sprint's scope remains unverified.

## QA Test Plan

1. ~~On a `gcc`-capable runner: `go build ./...`, `go vet ./...`, `go test ./... -count=1` with `CGO_ENABLED=1`~~ — **done** (see Verification above); re-run on CI to confirm the fix holds on the Linux `ubuntu-cgo` runner too, not just this Windows+MinGW setup.
2. Load a rule YAML with a missing or invalid `lifecycle` value; confirm the loader rejects it with a clear per-rule error, and that a directory with multiple bad rules reports all of them, not just the first.
3. ~~Run `cmd/zerostrike-bench --corpus benchmark/corpus --min-recall 0.90 --max-fp 0`, with and without `--enable-graphs`~~ — **done**, 100%/100%/0 FP both ways.
4. Scan a Python fixture with a taint-gated rule (e.g. SQL injection via `request.args`) with `--enable-graphs`; confirm `TaintContext.Path` traces from source to sink. Scan the same fixture without the flag; confirm `Path` is empty but the finding still fires. (Covered by `TestIntegration_EnableGraphsPopulatesTaintPath`, now passing — a manual `zerostrike scan --enable-graphs` against a real fixture file is still worth doing to see the JSON/HTML report shape.)
5. Scan a Python fixture where the tainted assignment is inside one arm of an `if`, with `--enable-graphs`; confirm the finding still fires (flow-insensitive verdict unaffected) — `Path` may legitimately be shorter or absent for that hop, per the documented branch-exit-point ceiling (still real, distinct from the statement-wrapper bug fixed above).
