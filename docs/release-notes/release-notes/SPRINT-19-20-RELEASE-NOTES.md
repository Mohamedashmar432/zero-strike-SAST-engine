# Sprint 19+20 Release Notes

## Summary

Sprint 19 (Reporting Hardening) and Sprint 20 (Caching & Incremental
Scanning) shipped as one merged release. Version bumps to **v0.14.0**.

Sprint 19 makes findings usable in real triage workflows: rationale/
remediation/taint-context on every finding, report grouping (by file,
rule, severity, or language) across JSON/HTML/SARIF, richer SARIF output
for GitHub Code Scanning, and reviewer-facing `rationale` content authored
for all 63 rules across all 7 languages. It also closes 3 rule gaps the
Sprint 17+18 QA pass flagged for Java (`ZS-JAVA-007/008/009`).

Sprint 20 makes the engine fast on repeat scans: a disk-backed finding/AST
cache keyed on file content hash, with versioned whole-bucket invalidation
(engine version, rule-set content hash, IR schema version) so a rule edit
or engine upgrade never serves stale results. This closes the previously
dead `--no-cache` flag — it now actually does something.

32 commits, 120 files changed (+5,627/−262 lines). Full build/vet/test
suite green throughout; several real bugs were found and fixed during
development rather than left for QA to discover — see "Bugs Found &
Fixed During Development" below, since QA should know what was already
caught versus what still needs fresh eyes.

---

## Sprint 19 — Reporting Hardening

### Finding enrichment

`core.Finding` gains three fields, populated for every SAST finding via
`internal/findings/builder.go`:

- **`Rationale`** — 2-4 sentences on what the matched pattern lets an
  attacker do and where it's exploitable. Distinct from the existing
  `description` field (which stays rule-author-facing: what's matched,
  known limitations).
- **`Remediation`** — the rule's existing `fix_suggestion` field, now
  actually surfaced on the finding (previously loaded but silently
  dropped).
- **`TaintContext`** — for taint-gated rules only: `SourceVar`,
  `SourceExpr` (the expression that introduced the taint, from a new
  `taint.BuildContext` alongside the existing `taint.Build`), and `Sink`
  (the rule's callee or assignment LHS).

### Report grouping

New `report.GroupBy` type (`file` / `rule` / `severity` / `language`) and
`report.GroupFindings`/`report.IsGrouped`, wired into all three reporters:

- **JSON** — `--group-by` unset stays exactly the current flat
  `Findings` array; any grouping mode switches to a `Groups` wrapper.
- **HTML** — always grouped (no flat mode fits the page layout); default
  is severity, matching today's behavior exactly. Along the way, fixed a
  real bug where badge color was tied to the *table's* severity class
  rather than each finding's own — harmless under severity-only grouping,
  but would have silently broken color-coding under file/rule/language
  grouping (mixed severities sharing one table).
- **SARIF** — deliberately **not** grouped (SARIF's `results` array is
  flat per spec); enrichment only (see below).

New `--group-by file|rule|severity|language` CLI flag, validated before
the scan runs (fails fast on a typo, not after an expensive scan).

### SARIF enrichment

`internal/report/sarif/sarif.go` now emits, per rule: `fullDescription`
(from `Rationale`), `help` (`Rationale` + `Remediation`), `helpUri` (first
`References` entry), and `properties.tags` (CWE/OWASP in GitHub
code-scanning convention, e.g. `external/cwe/cwe-611`,
`owasp:a05-2025`). Per result: `partialFingerprints` (the existing stable
`Fingerprint`, keyed `zerostrikeFingerprint/v1`). All new fields are
`omitempty` — SARIF consumers unaware of them see no change.

### Java rule gaps closed (from Sprint 17+18 QA)

| Rule | Finding | CWE / OWASP |
|---|---|---|
| ZS-JAVA-007 | `NoOpPasswordEncoder.getInstance()` — plaintext password storage | CWE-256 / A07:2025 |
| ZS-JAVA-008 | Short (≤16 char) hardcoded JWT/HMAC signing secret | CWE-326, CWE-798 / A04:2025 |
| ZS-JAVA-009 | `XMLInputFactory.newInstance()` — StAX XXE, the sibling of ZS-JAVA-003's DOM-parser check | CWE-611 / A05:2025 |

ZS-JAVA-009 ships as its own rule ID rather than extending ZS-JAVA-003's
match pattern — the engine's `MatchPattern.Callee` is one string per rule
by design, and multi-callee support would be a shared-schema change
affecting all 7 languages, out of scope here.

### Rationale content — all 63 rules

Every rule across Python (23), JS (10), TS (5), C# (6), Go (5), PHP (5),
and Java (9) now has a `rationale:` field. A new repo-wide completeness
test (`internal/rules/content_test.go`) asserts every embedded rule has
both `Rationale` and `FixSuggestion` non-empty — a regression gate for
future rule additions, not a one-time check.

---

## Sprint 20 — Caching & Incremental Scanning

### What gets cached

- **Finding cache** — keyed by file path + SHA-256 of content. On a hit
  (hash matches), `processFile` skips parsing, analysis, and matching
  entirely, returning the cached findings directly. Diagnostics (parse
  warnings) are **not** replayed on a cache hit — a deliberate, documented
  simplification (diagnostics are advisory, findings are not).
- **AST/IR cache** — keyed by content hash alone, so it survives a rule
  edit (parsing doesn't depend on rules). On a hit, skips only
  tree-sitter parsing; analysis and rule matching always still run,
  since rules may have changed even when the file hasn't.

Both live under `<scanned-root>/.zerostrike/cache/`, already excluded
from the file walker and now correctly excluded from git status at any
depth (see the `.gitignore` fix below).

### Invalidation

`cache.Open` compares a `Meta{FormatVersion, EngineVersion, RuleSetHash,
IRSchemaVersion}` against what's on disk from the last run, wiping
whichever bucket a mismatch affects — always a whole-bucket wipe, never
an attempt at partial invalidation, per this cache's stated design
principle that under-invalidating (stale results) is worse than
over-invalidating (an unneeded re-scan):

| Trigger | Wipes |
|---|---|
| Engine version changed | findings + AST |
| Rule set content changed (any rule edited/added/removed) | findings only — AST survives, since parsing doesn't depend on rules |
| IR schema version bumped | AST only |
| Cache format version bumped, or `meta.json` corrupt/unreadable | everything |

`RuleSetHash` comes from a new `rules.HashRuleSet` — a deterministic
SHA-256 over rule file content (not parsed structs, to avoid Go
map/struct-ordering fragility), hardened against two real risks found
during development: a transient I/O error being silently treated as "no
rules here" (now propagated as an error, not swallowed), and Windows/Linux
CRLF-vs-LF checkouts of the same commit producing different hashes for
byte-identical rule content (now normalized before hashing).

### `--no-cache`

Previously accepted by the CLI but wired to nothing. Now genuinely
disables caching end-to-end — confirmed via a pipeline-level test that
`.zerostrike/cache` is never created on disk with the flag set.

### Concurrency

All cache writes go through a single atomic-write primitive (temp file +
`os.Rename` in the same directory) — no mutex needed, since a concurrent
reader always sees either the complete old file or the complete new one.
Stress-tested with concurrent goroutines (not verifiable under Go's race
detector in this dev environment — see "Known Limitations"); surfaced a
real, documented finding: on Windows, a burst of renames targeting the
*same* destination file can transiently fail with "Access is denied"
(AV/filesystem-filter-driver interference), at rates up to ~98% in a
worst-case stress test. No corruption was ever observed — failed renames
cleanly leave the previous file untouched — and this scenario is
structurally impossible in real usage anyway, since each file is
processed by exactly one worker per scan.

---

## Bugs Found & Fixed During Development

QA should know these were already caught, not left for testing to find:

1. **A Java rule fixture would have double-fired two rules and failed
   CI's accuracy gate** — `ZS-JAVA-008`'s test fixture used a variable
   named `jwtSecret`, which also matches `ZS-JAVA-005`'s broader
   "any credential-shaped name" pattern. Renamed to `jwtSigningKey`.
2. **IR flattening aliased the live parse tree's `Attrs` map** instead of
   copying it — a future cache-write mutation could have silently
   corrupted the in-memory tree still in use elsewhere in the same scan.
3. **A cache write inconsistency window**: calling `Set` and `PutFindings`
   independently could leave a record whose content-hash matches the
   current file but whose findings are from a stale prior version — a
   "hit" that looks valid but returns wrong data. Fixed by adding
   `PutRecord`, which writes both atomically as one unit; this is now the
   only write path the scanner uses.
4. **HTML report badge coloring** was tied to the enclosing table's
   severity, not each finding's own — see "Report grouping" above.
5. **`.gitignore` never actually matched `.zerostrike/` cache
   directories** outside the repo root (a gitignore pattern with a slash
   in the middle is anchored to the `.gitignore` file's own directory,
   not recursive) — confirmed via `git status` showing untracked cache
   dirs after running the benchmark tool against `benchmark/corpus/*`.
   Fixed with `**/.zerostrike/`.

---

## Files Changed (by area)

| Area | Representative paths |
|---|---|
| Finding enrichment | `internal/core/finding.go`, `internal/findings/builder.go`, `internal/analyzer/taint/taint.go`, `internal/engine/engine.go` |
| Report grouping + SARIF | `internal/report/report.go`, `internal/report/{json,html,sarif}/*.go`, `cmd/zerostrike/scan.go` |
| Rule content (63 files) | `internal/rules/data/**/*.yaml` |
| New Java rules | `internal/rules/data/java/ZS-JAVA-{007,008,009}.yaml`, matching `testdata/java/` and `benchmark/corpus/java/` fixtures |
| Rule completeness test | `internal/rules/content_test.go` |
| Version consolidation | `internal/version/version.go` (new), `cmd/zerostrike/main.go`, `cmd/zerostrike-bench/main.go` |
| Rule hashing | `internal/rules/hash.go` (new) |
| IR serialization | `internal/ir/serialize.go` (new) |
| Disk cache | `internal/cache/{diskcache,diskastcache,meta,noop,findingstore}.go` (new) |
| Cache wiring | `internal/scanner/sast/{sast,caching}.go`, `internal/pipeline/scanner.go` |
| Concurrency tests | `internal/cache/concurrency_test.go` (new) |
| CI | `.github/workflows/ci.yml` (new `cache-perf` job) |
| Git hygiene | `.gitignore` |

---

## Test Results

`go build ./...`, `go vet ./...`, and `go test ./... -count=1` all pass —
verified in this no-CGo dev environment (`CGO_ENABLED=0`, no `gcc`) after
every commit throughout development, and again on the final merged
result. `go run ./cmd/zerostrike-bench --corpus benchmark/corpus` reports
`FP=0` (no regressions in what's measurable without CGo — recall reads
low here since no-CGo registers zero SAST parsers, which is expected and
matches every prior sprint's disclosed constraint).

**CGo path not compiled or run locally** — same disclosed constraint as
every prior language/engine sprint. Everything touching the tree-sitter
parse path, the real taint/rule-matching behavior on a cache-rebuilt IR
tree, and `processFile`'s actual hit/miss control flow was verified by
careful code reading and by isolating the CGo-independent pure logic
(hashing, JSON encode/decode of IR, cache read/write) into separately
testable files — but genuinely needs a green run on CI's `ubuntu-cgo`
leg before being considered fully proven.

---

## Known Limitations

- **No cache observability.** A `cache.Open` failure (e.g. an unwritable
  scan root) silently falls back to no caching — safe, but invisible; a
  user with a broken cache on their CI runner has no way to find out
  short of reading source. `report.ScanStats.FilesCached` has existed
  since Sprint 1 but is still never populated — cache hits produce no
  visible signal anywhere in report or CLI output.
- **Cache location is not configurable** — always
  `<scan-root>/.zerostrike/cache`. This makes the cache a no-op in CI
  patterns that clone a fresh checkout every run (exactly the environment
  that would benefit most from it); fine for the primary target use case
  (local dev, repeated scans of a persistent checkout).
- **Windows rename-contention residual risk** (see "Concurrency" above):
  confirmed non-corrupting and confirmed unreachable via concurrent
  writes in this codebase's actual usage pattern, but a lower-rate
  version of the same failure mode could in principle still affect an
  ordinary *sequential* single-writer cache write on an affected Windows
  host, silently reducing cache hit rate (never correctness). Documented
  on `atomicWriteFile`; no retry logic implemented — flagged as a
  candidate follow-up, not fixed here.
- **One CGo-only integration test still needed**: `processFile`'s actual
  cache-hit/cache-miss control flow, and whether analysis behaves
  identically on a cache-rebuilt IR tree versus a freshly parsed one, can
  only be verified end-to-end on a CGo-capable runner. A TODO for this
  lives in `internal/scanner/sast/caching_test.go`.
- Every language-specific/rule-specific known limitation from prior
  sprints (ZS-JAVA-001/002's receiver-name dependency, Maven version-range
  approximation, Ruby deferred, etc.) still applies unchanged — this
  sprint didn't touch that surface.

---

## QA Test Plan

**Environment requirement:** SAST rule matching (all `ZS-*` SAST rules
across all 7 languages, and the AST cache's real behavior) requires a
CGo-capable build (`gcc`/`cc` on PATH, default `CGO_ENABLED=1`). Confirm
`go env CGO_ENABLED` before starting — on a no-CGo machine, everything
below involving SAST findings or the AST cache will show zero SAST
results by design, not a bug. Secrets/SCA/framework-misconfiguration
scanning and the finding cache's plumbing (though not its real payoff)
are still exercisable without CGo.

### Reporting Hardening

1. Scan any fixture with findings (e.g. `testdata/python`) with each
   `--format` (`json`, `html`, `sarif`). Confirm every finding shows a
   non-empty, specific `Rationale` and `Remediation` (not boilerplate).
2. For a taint-gated rule (e.g. a Python SQLi/command-injection finding),
   confirm `TaintContext` is populated with a plausible source/sink; for
   a non-taint-gated rule, confirm it's absent (not an empty struct).
3. Try `--group-by file`, `--group-by rule`, `--group-by severity`,
   `--group-by language` with `--format json` and `--format html`.
   Confirm the JSON output switches from a flat `Findings` array to a
   `Groups` array; confirm HTML sections/headings match the chosen mode
   (and that file/rule/language labels are NOT capitalized, only severity
   labels are). Try an invalid value (`--group-by bogus`) and confirm a
   clear error before any scanning starts.
4. With mixed-severity findings grouped by something other than
   severity (e.g. `--group-by file` on a fixture with both high and low
   findings in one file), confirm each finding's badge color in the HTML
   report matches ITS OWN severity, not a single color for the whole
   group (this was a real bug, fixed — worth double-checking).
5. Open the SARIF output in a JSON viewer or upload it to GitHub Code
   Scanning (if available) — confirm `help`, `helpUri`, and
   `properties.tags` are present and sensible per finding.
6. Scan a Java fixture containing `NoOpPasswordEncoder.getInstance()`, a
   short hardcoded JWT secret, and `XMLInputFactory.newInstance()` —
   confirm `ZS-JAVA-007`, `ZS-JAVA-008`, `ZS-JAVA-009` fire respectively.

### Caching & Incremental Scanning

7. Scan a directory twice in a row (no flags). Confirm
   `<root>/.zerostrike/cache/meta.json` appears after the first run, and
   that the SECOND run's findings are byte-for-byte identical to the
   first (same rule set, same file content).
8. Time both runs. On a CGo-capable machine with a large-ish codebase,
   the second (warm) run should be noticeably faster — this is the
   actual point of the sprint, worth a real before/after measurement,
   not just a functional check.
9. Edit or add a rule YAML file (or point `--rules` at a different
   directory) and re-scan the SAME root. Confirm
   `.zerostrike/cache/findings/` gets cleared (next scan re-computes
   findings) while `.zerostrike/cache/ir/` is untouched — this is the
   core invalidation guarantee; a regression here means the cache could
   serve stale findings after a rule change.
10. Run with `--no-cache`. Confirm `.zerostrike/cache` is never created
    at all.
11. Run concurrently against a large repo with multiple workers
    (`--workers N` for N > 1) a few times in a row. Confirm no crashes,
    no corrupted-looking output, and consistent finding counts run to
    run — this exercises the concurrency behavior that was stress-tested
    in isolation but not yet end-to-end on a real multi-file scan.
12. Manually corrupt or truncate a file under `.zerostrike/cache/ir/` and
    re-scan. Confirm the scan still succeeds (degrades to a fresh parse
    for that file) rather than failing.

### Regression pass

13. Re-run the standard per-language fixture scans
    (`testdata/{python,javascript,typescript,csharp,go,php,java}`) and
    confirm finding counts/rule IDs match Sprint 17+18's baseline —
    nothing in this sprint should have changed detection behavior for
    existing rules, only added rationale/remediation/taint-context
    metadata and the 3 new Java rules.
14. Run `cmd/zerostrike-bench --corpus benchmark/corpus --min-recall 0.90
    --max-fp 0` on a CGo-capable machine and confirm it passes (this is
    CI's own accuracy gate — a good single command to confirm nothing
    regressed).
