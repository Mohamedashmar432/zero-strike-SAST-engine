# Sprint 23 Release Notes — v0.16.0

## Summary

Sprint 21+22 (v0.15.0) shipped rule lifecycle governance and a CFG/DFG graph
layer for Python taint tracking, and was unusually disciplined about naming
its own limitations rather than hiding them. Sprint 23 closes the two gaps
that were sized to fit in one sprint — a CFG branch-exit-point ceiling and a
22-rule benchmark corpus coverage backlog — and leaves the third (CallGraph
/ interprocedural taint) explicitly deferred, since research this sprint
confirmed it needs a much larger architectural change (see "Out of scope"
below).

## Fixed: CFG branch-exit-point ceiling

`internal/graph/graph.go`'s sequential fall-through pass used to wire an
`if`/`try` **header** node to the next sibling statement, not each branch's
actual last statement — so a definition made inside only one arm of an `if`
was never confirmed as reaching the code after the `if`, and
`TaintContext.Path` silently came back empty for that (common) shape.

Fixed via a new `blockExitNodes` helper that recursively resolves the real
CFG exit point(s) of a statement: normally the statement itself, but for an
`If` it's each branch's own exit(s) (plus the header itself when there's no
`else`, since the false path never enters a block), and for a `Try` it's the
main body's exit. Loop headers (`For`/`While`) were already correct and are
unchanged — their header-to-next edge already models "loop condition false,
fall through" accurately.

- 4 new unit tests in `internal/graph/graph_test.go`: if/else where both
  branches' defs should reach the join, if-with-no-else where the header
  itself is also a join source, nested if-inside-if (exits recurse through
  both levels), and try where the join comes from the body's last statement,
  not the header. All 15 pre-existing graph tests are unaffected.
- New integration test
  `TestIntegration_EnableGraphsPopulatesTaintPathAcrossIfBranch` in
  `internal/engine/integration_test.go`: the exact scenario
  `docs/roadmap/SPRINT-22-GRAPH-LAYER-CFG-DFG.md` predicted would have an
  empty `Path` now asserts `Path` is populated.
- No changes needed in `internal/analyzer/taint/taint.go` — `extendPath`
  already degraded gracefully when the DFG couldn't confirm a reaching def;
  it simply succeeds more often now that the CFG has real join edges.

## Closed: 22-rule benchmark corpus coverage gap

`TestAllRules_HaveCoverageInBenchmarkCorpus` (informational-only, added last
sprint) reported 22 of 63 released rules with no benchmark fixture. All 22
now have one: `cases/vuln_*.{py,js,ts}` fixtures under
`benchmark/corpus/{python,js,ts}/`, each wired into the language's
`manifest.yaml` with an `expect:` entry. The audit test now reports 0
missing rules.

## Bug found and fixed while adding corpus fixtures

Adding a fixture for `ZS-PY-015` (`urllib.request.urlopen()`) surfaced a
real, pre-existing bug: `internal/engine.go`'s `attributeText` only read
direct `Identifier` children of an attribute node, so a 3+-segment dotted
callee (`urllib.request.urlopen`, which tree-sitter parses as a **nested**
attribute — `attribute(attribute(urllib, request), urlopen)`) resolved to
an empty/partial callee text and never matched. This is the only rule in
the entire 63-rule set with a 3-segment callee, which is why the coverage
gap had hidden it since the rule was added. Fixed by making `attributeText`
recurse into nested `NodeKindAttribute` children; 2-segment chains (already
direct `Identifier` children) are unaffected. Verified via a standalone IR
dump of `urllib.request.urlopen(url)` confirming the nested shape, then via
the fixed benchmark run reaching TP=75/FP=0/FN=0.

## Also found: stale on-disk finding cache masked the fix during verification

While validating the `attributeText` fix, the accuracy benchmark kept
reporting the same `ZS-PY-015` false negative even after the fix compiled
cleanly. Root cause: `benchmark/corpus/*/.zerostrike/cache/` (gitignored,
content-hash-keyed finding cache) had cached the "no findings" result from
before the fix, and the cache key doesn't include an engine/rule-set
version — exactly the caching risk `internal/version/version.go`'s own doc
comment flags as "later" work (version-based cache invalidation). Clearing
the stale cache directories resolved it immediately. Not fixed this sprint
(out of scope, same "later" already on record) — noted here so the next
person debugging a benchmark run that doesn't reflect a code change checks
for stale `.zerostrike/cache/` dirs first.

## Out of scope: CallGraph / interprocedural taint

Confirmed via research, not built: `graph.CallGraph` needs
`SASTScanner.Scan()` restructured into two phases (a global symbol/summary
pass across all files, then a matching pass), a project-level symbol table
(`internal/symboltable` is explicitly single-file today), and reconciling
the per-file finding-cache short-circuit so cached files still contribute
their exported function summaries to the global pass. This is 3-4x the size
of this sprint's two items combined, with no concrete motivating false
negative yet observed. Tracked as a Sprint 24+ candidate.

## Verification

- `go build ./...` / `go vet ./...` — clean under both `CGO_ENABLED=0` and
  `CGO_ENABLED=1` (MinGW-w64 gcc).
- `go test ./... -count=1` — all 31 packages pass under both.
- `zerostrike-bench --corpus benchmark/corpus --min-recall 0.90 --max-fp 0`:
  **TP=75 FP=0 FN=0, precision=100.00%, recall=100.00%** (up from TP=53
  FP=0 FN=0 last sprint — the 22 new fixtures plus the `ZS-PY-015` fix).
- `TestAllRules_HaveCoverageInBenchmarkCorpus`: 0 missing (down from 22).
- Still open from last sprint: independent confirmation of the
  `flattenStatements` CGO fix on the real `ubuntu-cgo` GitHub Actions
  runner (only ever verified locally via MinGW). Pushing this sprint's
  commits exercises that CI leg again.
