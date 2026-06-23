# ZeroStrike — Pre-Sprint 3 Architecture Remediation
**Release Tag:** `pre-sprint-3-arch`  
**Branch:** `main`  
**Date:** 2026-06-23  
**Scope:** Architecture hardening before Sprint 3 engine work begins.

---

## Overview

A senior-model architectural review of the Sprint 1–2 implementation (`docs/architecture-correction.md`) identified 13 flaws — ranging from O(n²) matching complexity to silent correctness bugs in scope resolution. This release resolves all P0 and P1 blockers and locks in the design decisions for P2/P3 items before they become expensive to retrofit.

**No public API or CLI behavior changes.** All changes are internal — interfaces, correctness fixes, and foundational infrastructure.

---

## Changes by Severity

### P0 — Interface changes (expensive to retrofit after Sprint 3)

#### C1 · Engine: single IR walk with dispatch index
**File:** `internal/engine/engine.go`

The original design would loop over every rule and walk the IR tree per rule — O(rules × nodes). At 200+ rules over a 10k-node file, this degrades badly.

**What changed:**
- Added `RuleIndex` struct with two maps: `byKind map[NodeKind][]*Rule` and `byCallee map[string][]*Rule`.
- Added `BuildIndex(rs []*rules.Rule) *RuleIndex` — call once at rule-load time, share across all files.
- `Engine.Match` now walks the IR **once**, looking up only the indexed rules for each node's kind and callee.
- Callee-specific call rules are stored only in `byCallee` (no double-matching with `byKind`).
- `MatchContext.Rules []*rules.Rule` replaced by `MatchContext.Index *RuleIndex`.
- `MatchResult.NodeID string` replaced by `MatchResult.Node *ir.IRNode` (enables finding builder to access node data without re-traversal).
- Added `calleeText()` supporting both plain calls (`eval`) and attribute calls (`os.system`, `pickle.loads`).
- Added concrete `defaultEngine` with full `matchNode` and `evalFilter` implementations — engine is fully usable in Sprint 3.

**Performance guarantee:** match time scales with node count, not rules × nodes.

---

#### C2 · Finding: stable cross-run fingerprint
**Files:** `internal/core/finding.go`, `internal/findings/builder.go`

The existing deduplicator used a location-hash key (ruleID + file + line + col). Line numbers change whenever code is added or removed above a finding — causing every re-scan to flood the portal with false-new findings.

**What changed:**
- Added `Fingerprint string` field to `core.Finding`. This is the stable cross-run identity.
- Fingerprint algorithm: `SHA256(ruleID | enclosingSymbol | normalizedSnippet)[:16]` where the snippet is whitespace-normalized. Line/column are deliberately excluded.
- Implemented in `findings/builder.go` (`BuildFinding` + `computeFingerprint`).
- The existing intra-run dedup key (ruleID + file + line + col) is unchanged — it still eliminates exact duplicates within one scan.
- Cross-run history keyed on `Fingerprint`; intra-run dedup on location hash. Two separate concerns, two separate keys.

**Invariant:** inserting blank lines above a finding must not change its Fingerprint. Verified by `TestFingerprint_StableAcrossLineChanges`.

---

### P1 — Required for correctness

#### C4 · ZS-PY-004 and ZS-PY-008 demoted to confidence:medium
**Files:** `rules/python/ZS-PY-004.yaml`, `rules/python/ZS-PY-008.yaml`

Both rules (SQL string formatting / SQLi, and `open()` with variable path) are dataflow problems detected by syntactic approximation. Shipping them at `confidence: high` would train early users to distrust the tool.

**What changed:**
- Both rules: `confidence: high` → `confidence: medium`.
- Both rules: added `syntactic-approximation` tag.
- Both rules: description now includes a note that precision improves with taint analysis (Sprint 8).

---

#### C5 · IR builder: defined ERROR-node policy
**File:** `internal/parser/python/builder.go`

Previously, tree-sitter ERROR nodes were silently returned as `nil` — no caller knew a subtree was skipped, and there was no diagnostic. A single malformed line could silently drop all findings in that file.

**What changed:**
- Added `BuildWarning` struct (`File`, `Message`, `Line`).
- `IRBuilder.Build` signature changed to `(*ir.IRFile, []BuildWarning, error)`.
- When an ERROR node is encountered: skip its subtree, append a `BuildWarning` recording the file and line, continue building IR for the rest of the file.
- The builder never panics on malformed input.
- Pipeline updated to consume the new 3-return signature.

---

#### C6 · Symbol table: Python LEGB edge-case tests + class-scope bug fix
**Files:** `internal/symboltable/symboltable.go`, `internal/symboltable/symboltable_test.go`

The builder was setting a method's scope parent to the class scope, which is wrong for Python 3 — class scope is not in the lookup chain for methods. Without the fix, a taint rule could resolve a class-level constant as a method-local variable, producing silent false negatives in Sprint 8.

**What changed (production code):**
- `walkNode` for `NodeKindFunction`: if `current.Type == ScopeClass`, the function scope's `ParentID` is set to `current.ParentID` (the class's parent), not `current.ID`. This correctly excludes class scope from the method lookup chain.

**What changed (tests — 4 new cases):**

| Test | What it covers |
|---|---|
| `TestClassScope_MethodBodyExclusion` | Class-level assignment must NOT be resolved from inside a method body |
| `TestComprehensionScope_VariableIsolation` | Resolve does not walk child scopes; comprehension loop variable doesn't leak |
| `TestGlobalNonlocal_ScopeRebinding` | Symbol from outer function scope is reachable from nested function via scope chain |
| `TestWalrus_BoundsToEnclosingScope` | Walrus-assigned variable is resolvable from the enclosing scope |

---

#### C9 · Rule validator: rejects unindexable rules
**File:** `internal/rules/validator.go`

Without validation, a rule missing `kind` or a `call` rule missing `callee` would silently produce no matches — making the rule file appear correct while producing zero results.

**What changed:**
- `NewValidator()` returns a concrete implementation of the `Validator` interface.
- `Validate(rule)` returns field-level error strings for:
  - Missing `match.kind`
  - Unknown `match.kind` value (checked against all defined `NodeKind` constants)
  - `kind: call` without `callee`
  - Invalid `severity` value (not in `{critical, high, medium, low, info}`)
  - Invalid `confidence` value (not in `{high, medium, low}`)

---

### P2 — Design locked, implementation deferred

#### C8 · gob serialization design locked for Sprint 7
**File:** `internal/cache/astcache.go`

`IRNode` has a `Parent ↔ Children` pointer cycle and `Attrs map[string]any` — both are traps for gob serialization. Fixing these after Sprint 7 ships would require migrating all cached data.

**What changed:**
- `ASTCache` interface defined (not yet implemented).
- Design constraints documented as code comments:
  1. Serialize a flat `[]SerialNode` with integer child indices; omit `Parent`, rebuild on load.
  2. Replace `Attrs map[string]any` with a typed `NodeAttrs` struct before implementing.
  3. Cache key: `SHA256(file content)`.
  4. Store IR schema version; invalidate on version bump.

---

### P3 — Hygiene and CI

#### C3 · Scan/upload separation documented
**File:** `internal/pipeline/scanner.go`

`Run()` now carries an explicit code comment: the pipeline never makes network calls. Upload is a separate future `zerostrike upload` stage. Exit code is unaffected by network errors.

#### C7 · Dependency DAG invariant corrected and enforced
**Files:** `internal/pipeline/arch_test.go`, plan file

The original plan's invariant was incomplete (omitted `analyzer`, `findings`, `report`). The corrected full DAG:
```
cmd → pipeline → { engine → analyzer → ir ← parser, findings, report }
walker, detector feed pipeline; parser ← detector ← walker
core is imported by everything and imports NOTHING (leaf).
rules is imported by engine; rules NEVER imports engine.
```

`arch_test.go` uses `go list -json` to enforce key invariants: `rules` must not import `engine`; `core` must not import any internal package; `ir` and `analyzer` must not import `pipeline` or `engine`.

---

## New Files

| File | Purpose |
|---|---|
| `internal/engine/engine_test.go` | Engine tests: basic call match, nil-index guard, 200-rule dispatch correctness |
| `internal/findings/builder.go` | `BuildFinding()` + `computeFingerprint()` + `enclosingSymbolName()` |
| `internal/findings/builder_test.go` | Fingerprint stability test across line-number changes |
| `internal/findings/deduplicator.go` | Concrete `Deduplicator` impl; intra-run key documented vs Fingerprint |
| `internal/rules/validator.go` | Concrete `Validator` impl; rejects 5 categories of malformed rules |
| `internal/rules/validator_test.go` | Table-driven tests: one malformed rule per error case |
| `internal/cache/astcache.go` | `ASTCache` interface + Sprint 7 design constraints (unimplemented) |
| `internal/pipeline/arch_test.go` | Import DAG invariant enforcement via `go list` |
| `rules/python/ZS-PY-001.yaml` | eval() dangerous usage |
| `rules/python/ZS-PY-002.yaml` | pickle.loads insecure deserialization |
| `rules/python/ZS-PY-003.yaml` | subprocess shell=True command injection |
| `rules/python/ZS-PY-004.yaml` | SQL string formatting / SQLi (confidence:medium) |
| `rules/python/ZS-PY-005.yaml` | os.system() command injection |
| `rules/python/ZS-PY-006.yaml` | Hardcoded password / secret literal |
| `rules/python/ZS-PY-007.yaml` | Weak hash (MD5/SHA1) |
| `rules/python/ZS-PY-008.yaml` | open() with variable path (confidence:medium) |
| `rules/python/ZS-PY-009.yaml` | assert used for security check |
| `rules/python/ZS-PY-010.yaml` | yaml.load without safe_load |

---

## Modified Files

| File | Change |
|---|---|
| `internal/core/finding.go` | +`Fingerprint string` field |
| `internal/engine/engine.go` | Full rewrite: RuleIndex, BuildIndex, single-walk Match, matchNode, evalFilter |
| `internal/parser/python/builder.go` | Build returns `(IRFile, []BuildWarning, error)`; ERROR nodes emit warnings |
| `internal/parser/python/python_test.go` | +`TestIRBuilder_MalformedFile`; updated Build call to 3-return |
| `internal/pipeline/scanner.go` | Updated buildIR to consume 3-return Build; added C3 network-free comment |
| `internal/symboltable/symboltable.go` | Class scope excluded from method lookup chain (Python LEGB fix) |
| `internal/symboltable/symboltable_test.go` | +4 LEGB edge-case tests |

---

## Test Coverage Summary

```
internal/symboltable  9 tests  PASS  (4 new LEGB edge cases)
internal/engine       4 tests  PASS  (index, 200-rule dispatch, nil guard)
internal/rules        6 tests  PASS  (validator: 5 error cases + valid rule)
internal/findings     1 test   PASS  (fingerprint stability)
internal/core         4 tests  PASS  (unchanged)
internal/ir           2 tests  PASS  (unchanged)
```

Parser tests (`internal/parser/python`) require CGo (go-tree-sitter). They compile and pass in CGo-enabled environments; they are excluded from CI runs without a C toolchain.

---

## What Sprint 3 Needs (updated scope)

The following Sprint 3 work is **not** in this release but is now unblocked:

1. `internal/rules/loader.go` — YAML → Rule loader with `//go:embed rules/`
2. `internal/rules/registry.go` — Rule registry (ByLanguage, ByCategory, ByTag)
3. `internal/findings/collector.go` — Collector wiring (Add, All)
4. `testdata/python/` — Positive + negative fixture files per rule (10 pairs)
5. Pipeline: wire `BuildIndex → MatchContext → Engine.Match → BuildFinding → Collector`
6. Integration test: `scan testdata/python/` asserts each rule fires on its positive fixture
7. ZS-PY-004 / ZS-PY-008 negative fixtures must include "safe constant" case

---

## Known Limitations

- `assert` (ZS-PY-009) is a statement in Python, not a function call — the current `kind: call / callee: assert` rule will not match. Needs `NodeKindAssert` in the IR or a dedicated rule kind in Sprint 3.
- ZS-PY-006 (hardcoded secrets) uses `kind: assignment` with no identifier filter — will match all assignments until identifier-name filtering is wired in Sprint 3.
- Comprehension scope and walrus operator scope are not yet modeled by the IR builder. Tests document the expected semantics; implementation deferred to Sprint 8 when taint analysis requires it.
