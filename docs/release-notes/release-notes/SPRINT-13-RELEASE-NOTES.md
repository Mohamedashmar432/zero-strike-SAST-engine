# Sprint 13 Release Notes

## Summary

Sprint 13 ships three merged workstreams and a version bump to **v0.10.0**. **Part A** replaces the per-language switch scattered across five files with a single registration point (`internal/langreg`): adding a language is now a `register.go` + one embed-glob line, unsupported languages fail at startup instead of silently per file, and a verified double-parse bug on every Python file is gone. **Part B** completes C# end-to-end on the new registry — tree-sitter parser, IR builder, a 6-rule pack (`ZS-CS-001`–`006`), fixtures, and CI coverage — turning `--lang csharp` from a silent no-op into a working scan. **Part C** makes taint tracking meaningfully more precise: per-language source/sanitizer patterns, same-file interprocedural tracking via function summaries, and a fix for a verified bug where a tainted variable stayed tainted forever after a clean reassignment.

---

## Part A — Language Onboarding Registry Refactor

### What it does

- New package `internal/langreg`: `Entry{Language, NewBuilder func() ir.Builder, RuleDir}` with `Register` / `Get` / `All` (stable order). Language packages self-register from `init()` in a per-package `register.go`.
- `ir.Builder` corrected to the signature every language actually implements: `Build(path, source) (*IRFile, []BuildWarning, error)`. The three identical per-package `BuildWarning` structs are unified into `ir.BuildWarning`.
- `sast.go`'s `buildIR()` is now a single `langreg.Get(lang)` + `Build()` — no language switch. This also removes a real perf bug: the old Python case parsed **every file twice** (once via `pythonparser.New().Parse()`, then again inside `builder.Build()`, which self-parses). `ParseResult.Source` was the same byte slice passed in, so behavior is byte-identical with one parse fewer.
- `internal/rules/embed.go` gains `rules.RuleDirs`; `pipeline.loadAllRules()` iterates it instead of its own hardcoded copy.
- **Fail-fast**: `pipeline.New()` validates every `cfg.Languages` entry against `langreg` and errors at startup — previously an unsupported language (C# was the live example) failed silently per file, mid-scan, and produced an empty report with exit 0.
- Dead code deleted: `internal/parser/registry.go` (`parser.Registry` was never wired into any dispatch path, and its sibling `ir.Builder` didn't even match the builders' real signatures).

### What changes for users

```bash
# Before: silent empty scan. After (CGo-less build or unknown language):
$ zerostrike scan --lang csharp ./src
Error: pipeline.New: pipeline: unsupported language csharp: no parser registered (CGo-less builds register no parsers)
# exit 1, at startup — not a silent per-file no-op
```

On full (CGo) builds all previously supported languages behave identically — this is a pure refactor for Python/JS/TS.

### QA test cases

**TC-13.1 — Unregistered language fails at startup**
`zerostrike scan --lang csharp .` on a `CGO_ENABLED=0` build → exit 1 with `unsupported language csharp: no parser registered`. Covered by `TestPipelineNew_UnregisteredLanguageFailsFast` (runs under both CGo and no-CGo).

**TC-13.2 — Registered language passes validation**
`TestScanPipeline_Python` now passes `Languages: [python]` explicitly and still scans (CGo builds).

**TC-13.3 — No behavior change for existing languages**
Python/JS/TS scans of `testdata/` produce identical findings before/after (verified by the unchanged engine/pipeline integration suites; see Test Results for the CGo caveat).

---

## Part B — C# Completion

### What it does

`.cs` files are detected (mapping already existed), parsed via `github.com/smacker/go-tree-sitter/csharp`, converted to IR by `internal/parser/csharp/builder.go` (same shape as the JavaScript builder), and scanned through the Part A registry — no special-casing anywhere. Node-type names and field names (`left`/`right`/`name`/`parameters`/`initializer`…) were verified against the pinned grammar's `parser.c` rather than assumed; field lookups fall back to child-type scans defensively.

### Initial rule pack

| Rule | Finding | Match | CWE / OWASP |
|---|---|---|---|
| ZS-CS-001 | Command injection | `Process.Start(...)` + tainted argument | CWE-78 / A05:2025 |
| ZS-CS-002 | SQL injection | `new SqlCommand(...)` + tainted argument | CWE-89 / A05:2025 |
| ZS-CS-003 | Insecure deserialization | `new BinaryFormatter()` (any use is the risk) | CWE-502 / A08:2025 |
| ZS-CS-004 | XSS sink | `Response.Write(...)` + tainted argument | CWE-79 / A05:2025 |
| ZS-CS-005 | Weak crypto | `MD5.Create()` | CWE-327 / A04:2025 |
| ZS-CS-006 | Hardcoded credential | credential-named var = string literal | CWE-798 / A07:2025 |

### CLI usage

```bash
zerostrike scan --format json ./my-dotnet-app          # auto-detects .cs
zerostrike scan --lang csharp --format sarif ./src
```

### QA test cases

**TC-13.4 — Each rule fires on its fixture**
`testdata/csharp/vuln_*.cs` (one per rule) each produce their rule's finding; `testdata/csharp/clean.cs` produces none. Covered by `internal/engine/integration_csharp_test.go` (8 positive/negative cases) — CGo builds.

**TC-13.5 — C# rules load and validate**
`TestLoader_CSharpRulesLoad` asserts all 6 IDs load from the embedded FS and pass the validator (runs under no-CGo too).

**TC-13.6 — CI exercises C# end-to-end**
`scan-e2e` gains a `Scan C# fixtures (JSON)` step over `testdata/csharp/` (findings expected on the CGo matrix leg; report uploaded as an artifact).

---

## Part C — Taint: Same-File Interprocedural + Sanitizers

### What it does

`internal/analyzer/taint` is rewritten around explicit per-assignment verdicts:

1. **Never-clears bug fixed.** Previously the tainted map was only ever set `true`: `x = request.args.get('id'); x = "safe"` left `x` tainted forever. Every assignment now overwrites its LHS entry with a fresh verdict.
2. **Sanitizers.** An RHS matching a sanitizer call clears taint — `x = html.escape(x)` un-taints `x` even though its argument is tainted. Patterns per language: Python (`bleach.clean`, `shlex.quote`, `html.escape`), JS/TS (`DOMPurify.sanitize`, `encodeURIComponent`), C# (`HttpUtility.HtmlEncode`, `WebUtility.HtmlEncode`, `Encoder.Default.Encode`).
3. **Per-language source patterns** (`internal/analyzer/taint/patterns.go`). The old single shared regex is split faithfully (Python vs JS/TS pieces) and C# is added (`Request.QueryString/Form/Params/Cookies`, `Console.ReadLine`). Config lives in Go, not in rule YAML — 23+ rules consume it through the existing `tainted_argument`/`tainted_rhs` filters with zero schema changes. Hand-built IR without a language falls back to the combined Python+JS set (preserves pre-split behavior).
4. **Same-file interprocedural tracking** (`internal/analyzer/taint/summary.go`). Every function gets a summary from its return statements: *pass-through* (returns one of its own parameters) and *always-tainted* (returns a source expression). An assignment whose RHS calls a same-file function — confirmed locally defined via the symbol table, so imports/stdlib names are ignored — is tainted when the summary says so. `y = get_user()` where `def get_user(): return request.args.get('id')` is now caught; nothing else could catch it (no tainted identifier appears at the call site).
5. **Prerequisites landed**: all four builders capture `Attrs["parameters"]` and `Attrs["return_expr"]`; `symboltable` now actually defines `SymbolParameter` symbols (previously a dead enum constant) in the function's own scope. `taint.Build` accepts the already-built `SymbolTable` from `analyzer.Analyze` instead of building a second one.

### QA test cases (all in `internal/analyzer/taint/taint_test.go`, no-CGo)

**TC-13.7 — Sanitizer clears taint**: `x = request.args.get('y'); x = html.escape(x)` → `x` not tainted.
**TC-13.8 — Clean reassignment clears taint** (regression for the fixed bug): `x = request.args.get('y'); x = "literal"` → `x` not tainted.
**TC-13.9 — Pass-through function**: helper returning its parameter, called with a tainted arg → receiving variable tainted.
**TC-13.10 — Always-tainted function**: helper returning a source, called with no args → receiving variable tainted; with `nil` symbol table the interprocedural step is disabled (negative control).
**TC-13.11 — Cross-function name reuse**: a clean same-named local in a different function is not contaminated.
**TC-13.12 — Augmented assignment preserves taint**: `x = source; x += "suffix"` → `x` stays tainted (see Additional Findings #2).
**TC-13.13 — Parameters become symbols**: `TestBuildFromIR_ParametersBecomeSymbols` resolves a parameter as `SymbolParameter` inside the function scope and not from module scope.

---

## Version Bump

`zerostrike --version` now reports **v0.10.0** (was `v0.9.0`).

---

## Files Changed

| File | Change |
|---|---|
| `internal/langreg/langreg.go` | New — language registry (`Entry`, `Register`/`Get`/`All`); pure Go, no cgo tag (see Additional Findings #5) |
| `internal/langreg/langreg_test.go` | New — 1 test (register/get/builder round-trip/stable order) |
| `internal/ir/builder.go` | `Builder` signature corrected to 3 return values; `ir.BuildWarning` added |
| `internal/parser/registry.go` | **Deleted** — dead `parser.Registry`, never wired into dispatch |
| `internal/parser/{python,javascript,typescript}/builder.go` | Local `BuildWarning` types deleted → `ir.BuildWarning`; `parameters`/`return_expr`/`augmented` attr capture added |
| `internal/parser/{python,javascript,typescript}/register.go` | New — `init()` registration with langreg (cgo) |
| `internal/parser/{python,javascript,typescript,csharp}/doc.go` | New — untagged package stubs so blank imports compile under `CGO_ENABLED=0` |
| `internal/parser/csharp/csharp.go` | Was a bare `package csharp` line — now the tree-sitter C# parser (cgo) |
| `internal/parser/csharp/builder.go` | New — C# CST→IR builder incl. params/returns/augmented/except-handler capture |
| `internal/parser/csharp/register.go` | New — registry entry for `data/csharp` |
| `internal/scanner/sast/sast.go` | `buildIR()` collapsed to registry dispatch (double-parse removed); language blank imports live here |
| `internal/rules/embed.go` | `data/csharp/*.yaml` embedded; `RuleDirs` var added |
| `internal/rules/data/csharp/ZS-CS-00{1..6}.yaml` | New — 6-rule C# pack |
| `internal/rules/loader_csharp_test.go` | New — 2 tests |
| `internal/pipeline/scanner.go` | `loadAllRules` iterates `rules.RuleDirs`; fail-fast language validation in `New()` |
| `internal/pipeline/validation_test.go` | New — fail-fast test (runs on CGo and no-CGo) |
| `internal/pipeline/scanner_integration_test.go` | `TestScanPipeline_Python` passes explicit `Languages` (positive validation path) |
| `internal/analyzer/taint/taint.go` | Rewritten — explicit verdicts, sanitizers, summaries, `SymbolTable` parameter, updated ceiling comment |
| `internal/analyzer/taint/patterns.go` | New — per-language source/sanitizer config |
| `internal/analyzer/taint/summary.go` | New — same-file function summaries |
| `internal/analyzer/taint/taint_test.go` | Expanded 6 → 13 tests |
| `internal/analyzer/analyzer.go` | Passes symbol table into `taint.Build`; `TaintedVars` doc updated |
| `internal/symboltable/symboltable.go` | Function parameters defined as `SymbolParameter` in function scope |
| `internal/symboltable/symboltable_test.go` | +1 test |
| `internal/engine/integration_csharp_test.go` | New — 8 C# rule integration tests (cgo) |
| `testdata/csharp/*.cs` | New — 6 positive fixtures + `clean.cs` negative |
| `cmd/zerostrike/main.go` | Language blank imports; version → `v0.10.0` |
| `.github/workflows/ci.yml` | `scan-e2e` scans `testdata/csharp/`, uploads `csharp-report.json` |

---

## Test Results

Full no-CGo suite (`CGO_ENABLED=0 go test ./... -count=1`) — **all packages pass**; `go build ./...` and `go vet ./...` clean:

```
ok  internal/analyzer
ok  internal/analyzer/taint    (6 → 13 tests: sanitizer, clean-reassignment, augmented,
                                pass-through, always-tainted, cross-function, nil-symbols, C# source)
ok  internal/core
ok  internal/detector
ok  internal/engine
ok  internal/findings
ok  internal/ir
ok  internal/langreg           (new package)
ok  internal/pipeline          (+ fail-fast validation test)
ok  internal/report/html
ok  internal/report/json
ok  internal/report/sarif
ok  internal/rules             (+ C# loader tests)
ok  internal/scanner/sca
ok  internal/scanner/secrets
ok  internal/symboltable       (+ parameter-symbol test)
ok  internal/walker
```

CLI smoke (no-CGo binary): `scan --format json testdata/csharp` walks 7 files, exits cleanly; `scan --lang csharp` fails fast at startup with a clear message (previously a silent empty report).

**CGo-gated tests not verified locally** — same GCC-less dev environment limitation as Sprints 11/12. All cgo files (`langreg` registrations, collapsed `buildIR`, the entire C# parser/builder, parameter/return capture in the Python/JS/TS builders, and the C# integration tests) are written, `gofmt -e`-syntax-verified, and reviewed against the pinned grammar's `parser.c` (node-type and field-name tables extracted from the module cache), but require the `test / ubuntu (CGo)` CI job to actually execute — the same job that verified Sprint 11's and 12's CGo code. Consequently the "byte-identical findings before/after" regression check for Part A rests on code equivalence (the collapsed dispatch performs the exact same `Build(path, source)` calls; `ParseResult.Source` was verified to be the same byte slice) plus CI, not on a local diff of scan outputs. The step-4 smoke scan showing all 6 C# findings could not be run locally for the same reason; the CI `scan-e2e` C# step covers it.

---

## Additional Findings

Concrete flaws/improvements found in touched code beyond the sprint spec, and what was done about each:

1. **Python double-parse (fixed, spec-confirmed).** `sast.go:140-152` parsed every Python file twice. Removed by the registry collapse; `parseResult.Source` was verified identical to the input bytes, so this is pure perf win. Side effect: a hypothetical Python parse-failure diagnostic now reads `python builder: …` instead of `parse <path>: …` (same underlying error, different wrapper — the pre-parse that produced the old prefix no longer exists).
2. **Augmented assignments would have become false negatives (found & fixed).** The mandated never-clears fix ("every assignment overwrites with a fresh verdict") is wrong for `x += y`: the prior value flows into the result, so `x = request.args…; x += " suffix"` would have been *cleared* by the fresh-verdict rule. The old sticky-taint model masked this. Fixed by capturing `Attrs["augmented"]` in all four builders (Python `augmented_assignment`, JS/TS `augmented_assignment_expression`, C# compound `operator != "="`) and OR-ing the previous verdict for augmented assignments. Regression test TC-13.12.
3. **The clears-fix trades false positives for possible false negatives (documented, deliberately not "fixed").** The tainted map is one final verdict per name per file. Before: any taint was sticky (FPs on clean reassignment — the reported bug). After: the *last* assignment in source order wins, so `x = source; sink(x); x = "safe"` no longer flags the sink (FN). Fixing this properly needs flow-sensitive per-node taint (CFG/DFG, deferred). Documented in `taint.go`'s ceiling comment and the test for TC-13.11.
4. **`internal/parser/registry.go` deleted.** Dead abstraction confirmed unused by grep; keeping it would have left two competing "registry" concepts after langreg landed.
5. **Spec deviation: `langreg` has no cgo build tag.** The spec assumed it needed one; it doesn't — it only references the `ir.Builder` *interface* (pure Go), not any cgo-gated implementation. Making it pure Go is what lets `pipeline.New()` validate languages and the fail-fast test run under `CGO_ENABLED=0`.
6. **Spec deviation: blank imports also live in `sast.go`, not only `main.go`.** With registrations only in `main.go`, every non-CLI consumer of the SAST scanner (the pipeline/engine test binaries, any future library use) would silently see an empty registry and fail exactly the way this sprint set out to eliminate. The cgo `sast.go` — the code that actually dispatches — now guarantees its own languages; `main.go` keeps the spec'd imports (harmless duplication). Untagged `doc.go` stubs were added per language package so `main.go`'s imports compile under `CGO_ENABLED=0`. Trade-off: adding a language still means one blank-import line in `sast.go`.
7. **ZS-CS-003 matches `new BinaryFormatter()`, not `.Deserialize(…)`.** Callee extraction on `formatter.Deserialize(stream)` yields `formatter.Deserialize` — receiver-variable-dependent, so an exact-callee rule can't target it. Matching the constructor is robust and matches Microsoft's guidance that *any* BinaryFormatter use is the vulnerability. Documented in the rule description.
8. **ZS-CS-005 covers `MD5.Create` only.** The rule schema allows one callee per rule; `SHA1.Create` needs a companion rule (mirrors how Python splits MD5/SHA1 into ZS-PY-010/011). Left for the next rule-pack pass.
9. **`--lang` on CGo-less builds now errors at startup (behavior change, intended).** Previously `--lang python` on a no-CGo build "succeeded" with SAST silently doing nothing. Fail-fast validation makes the degraded build honest; CI's no-CGo e2e legs don't pass `--lang`, so they are unaffected.
10. **Pre-existing gofmt drift (left alone).** Eight files unrelated to this sprint (`internal/findings/allowlist.go`, `internal/pipeline/config.go`, `internal/report/sarif/sarif.go`, `internal/scanner/sca/lockfile.go`, `internal/walker/fswalker.go`, and 3 test files) fail `gofmt -l`. Not touched, to keep this sprint's diff reviewable; worth a standalone `gofmt -w` commit.
11. **Text-level sanitizer model can be fooled (known, accepted).** `x = shlex.quote(a) + request.args.get('b')` matches the sanitizer pattern and clears taint despite the raw source in the same expression. Inherent to the regex-on-RHS-text model; noted in the ceiling comment.

---

## Known Limitations

- **Cross-file interprocedural taint is not implemented — same-file only.** A tainted value flowing through a function *imported from another file* is not tracked. Doing so requires restructuring `SASTScanner.Scan()` from its single-pass-per-file worker pool into a two-phase pipeline (global symbol/summary pass, then per-file matching) — explicitly deferred (see `docs/roadmap/SPRINT-22-GRAPH-LAYER-CFG-DFG.md`).
- **Taint remains file-scoped and flow-insensitive.** Last-assignment-wins per name: cross-function name collisions can still contaminate (taint-after-clean order) or over-clear (clean-after-taint order, Additional Findings #3). True flow sensitivity is the CFG/DFG sprint's job.
- **Go/PHP language rollout is intentionally not part of this sprint** — next sprint, once C# has proven the registry pattern in CI.
- **CGo path not compiled locally**: no `gcc` in the dev environment, so every cgo-gated change in this sprint (including the whole C# parser/builder) was verified by code review, grammar-table inspection, and `gofmt -e` only; the `test / ubuntu (CGo)` and `scan-e2e / ubuntu-cgo` CI jobs are the authoritative verification, as in Sprints 11/12.
- **Upstream C# grammar is incomplete** (its own package doc warns it "may return a partial or wrong AST"); ERROR subtrees are skipped with warnings, but odd C# constructs may silently produce no IR (and thus no findings).
- `--lang csharp` on `CGO_ENABLED=0` builds now fails fast by design (see Additional Findings #9).
