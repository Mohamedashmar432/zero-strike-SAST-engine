# Sprint 12 Release Notes

## Summary

Sprint 12 extends Sprint 11's two workstreams — taint tracking and OWASP Top 10:2025 coverage — from Python to **JavaScript and TypeScript**. Both languages started at the exact position Python was in before Sprint 11: 8 rules total, all tagged `A03:2021`, zero taint gating, zero coverage of A02/A07/A09/A10.

1. **Taint tracking (JS/TS)** — same file-scoped, intra-procedural algorithm as Python, extended with Express/browser source patterns (`req.query/body/params`, `location.search/hash`, `window.location`). One new mechanism was needed beyond what Python required: a `tainted_rhs` filter, because JS's highest-value sinks split between call arguments (`eval`, `document.write`, `Function`) and **assignment right-hand-sides** (`innerHTML`, `outerHTML`) — Python's taint-gated rules were all call-based, so this gap didn't show up until now.
2. **OWASP Top 10:2025 rule pack (JS/TS)** — all 8 existing rules re-tagged to `A05:2025`, plus 7 new rules closing A02, A07, A09, and A10.

Rule totals: JavaScript 5 → 10, TypeScript 3 → 5.

Version bumped to **v0.9.0**.

---

## New Feature: Taint Tracking (JS/TS)

### What changed

`internal/analyzer/taint/taint.go`'s source-pattern regex was extended (it's the same package Python uses — the algorithm was already language-agnostic, only the source patterns were Python-specific):

```
request\.(args|form|GET|POST|values)|(^|\W)input\(|sys\.argv|os\.environ\.get|req\.(query|body|params)|location\.(search|hash)|window\.location
```

**New filter: `Filter.TaintedRHS`** (`internal/rules/rules.go`, evaluated in `internal/engine/engine.go` via a new `rhsIsTainted` helper). Mirrors `TaintedArgument` but checks an assignment's right-hand-side subtree instead of a call's arguments — needed because `element.innerHTML = userInput` has no "call" to gate.

**Builder changes** (`internal/parser/javascript/builder.go`, `internal/parser/typescript/builder.go`): both gained an `rhs` capture on `assignment_expression`, mirroring what Python's builder already had.

### Rules upgraded

| Rule | Sink type | Filter added |
|------|-----------|---------------|
| ZS-JS-001 / ZS-TS-001 (eval) | call | `tainted_argument` |
| ZS-JS-003 / ZS-TS-003 (document.write) | call | `tainted_argument` |
| ZS-JS-004 (Function constructor) | call | `tainted_argument` |
| ZS-JS-002 / ZS-TS-002 (innerHTML) | assignment | `tainted_rhs` |
| ZS-JS-005 (outerHTML) | assignment | `tainted_rhs` |

### QA Test Cases

**TC-12.1 — Tainted eval() fires ZS-JS-001**
```javascript
let userInput = req.query.q;
eval(userInput);
```
Expected: 1 finding.

**TC-12.2 — Constant eval() no longer fires (false-positive fix)**
```javascript
eval("1+1");
```
Expected: 0 findings.

**TC-12.3 — Tainted innerHTML fires ZS-JS-002 (new TaintedRHS filter)**
```javascript
let userInput = req.query.name;
el.innerHTML = userInput;
```
Expected: 1 finding.

**TC-12.4 — Constant innerHTML no longer fires**
```javascript
el.innerHTML = "<b>hello</b>";
```
Expected: 0 findings.

**TC-12.5 — Taint transfers to TypeScript**
```typescript
let userInput: string = req.query.q;
eval(userInput);
```
Expected: ZS-TS-001 fires.

---

## New Feature: OWASP Top 10:2025 Rule Pack (JS/TS)

### Re-tag

All 8 existing rules (`ZS-JS-001..005`, `ZS-TS-001..003`) moved from `A03:2021` to `A05:2025`, matching Python's Sprint 11 re-tag.

### 7 new rules

Reused the exact same engine mechanisms Sprint 11 built for Python — no new engine capability except `TaintedRHS` was needed:

| Rule | Category | Pattern | Mechanism reused |
|------|----------|---------|-------------------|
| ZS-JS-006 / ZS-TS-004 | A02 | `https.request(url, {rejectUnauthorized: false})` | `Filter.Kwarg` — JS object-literal properties (`pair` nodes) map to the same `NodeKindKeywordArg` Python's `keyword_argument` uses, so this rule needed zero new engine code |
| ZS-JS-007 | A07 | Hardcoded credential (`password`/`secret`/`apiKey`/`token` = string literal) | `lhs_identifier` + `rhs_literal`, same as `ZS-PY-020` |
| ZS-JS-008 | A07 | `jwt.decode()` used where `jwt.verify()` belongs | Plain unconditional `callee` match — no Python equivalent, `decode()` never checks the signature at all |
| ZS-JS-009 | A09 | `console.log(password)` | `argument_identifier_matches`, same as `ZS-PY-022` |
| ZS-JS-010 / ZS-TS-005 | A10 | Empty `catch (e) {}` block | `has_empty_except_handler` — reused verbatim from Python's except-handler mechanism; JS catch clauses have no bare/typed distinction so only the "empty body" half of Python's A10 pair applies |

**Note on scope**: `ZS-JS-007`, `008`, `009` don't have TS equivalents — the design intentionally kept this sprint to 7 new rules rather than 10 by pairing only `ZS-JS-006`/`ZS-TS-004` and `ZS-JS-010`/`ZS-TS-005`. Since the match patterns are identical (TS shares JS's `assignment`/`call` IR node kinds), adding TS versions of the other three later is a copy-paste-relabel exercise, not new engine work.

### QA Test Cases

**TC-12.6 — rejectUnauthorized: false**
```javascript
https.request(url, {rejectUnauthorized: false});
```
Expected: ZS-JS-006 finding.

**TC-12.7 — Hardcoded credential**
```javascript
const password = "hunter2";
```
Expected: ZS-JS-007 finding.

**TC-12.8 — jwt.decode() misuse**
```javascript
const payload = jwt.decode(token);
```
Expected: ZS-JS-008 finding, severity critical.

**TC-12.9 — Empty catch block**
```javascript
try {
  doThing();
} catch (e) {
}
```
Expected: ZS-JS-010 finding.

**TC-12.10 — Non-empty catch block does not fire**
```javascript
try {
  doThing();
} catch (e) {
  console.error(e);
}
```
Expected: 0 findings for ZS-JS-010.

---

## Files Changed

| File | Change |
|------|--------|
| `internal/rules/rules.go` | `Filter.TaintedRHS` |
| `internal/rules/loader.go` | YAML parsing for `tainted_rhs` |
| `internal/engine/engine.go` | `rhsIsTainted` helper, wired into `evalFilter` |
| `internal/analyzer/taint/taint.go` | Source-pattern regex extended for Express/browser sources |
| `internal/parser/javascript/builder.go` | `pair` → `NodeKindKeywordArg` mapping, assignment `rhs` capture, `catch_clause` empty-body detection on `try` nodes |
| `internal/parser/typescript/builder.go` | Same 3 additions, mirroring JS |
| `internal/rules/data/js/ZS-JS-{001..005}.yaml` | Re-tagged to A05:2025, taint filters added |
| `internal/rules/data/ts/ZS-TS-{001..003}.yaml` | Same |
| `internal/rules/data/js/ZS-JS-{006..010}.yaml` | 5 new rules |
| `internal/rules/data/ts/ZS-TS-{004..005}.yaml` | 2 new rules |
| `internal/rules/loader_javascript_test.go` | Count assertions updated (JS ≥10, TS ≥5) |
| `internal/parser/javascript/javascript_test.go` | **New file** — 4 builder tests (no JS parser tests existed before this sprint) |
| `internal/parser/typescript/typescript_test.go` | +2 builder tests |
| `internal/engine/integration_javascript_test.go` | **New file** — 11 integration tests (no JS/TS integration tests existed before this sprint) |
| `internal/analyzer/taint/taint_test.go` | +2 tests for JS/TS source patterns |
| `internal/engine/engine_test.go` | +1 test (`TestMatch_TaintedRHS`) |
| `cmd/zerostrike/main.go` | Version `v0.9.0` |

---

## Test Results

Full no-CGo suite — **all packages pass** (`CGO_ENABLED=0 go test ./... -count=1`), `go vet ./...` clean.

**CGo-gated tests not verified locally** — same GCC-less dev environment limitation as Sprint 11. All new builder and integration tests are written and `gofmt -e`-syntax-verified but require the Linux CGo CI job (`test / ubuntu (CGo)`) to actually execute. This is the same job that already verified Sprint 11's CGo-gated code (Python builder + integration tests) with `conclusion: success` on GitHub Actions — the same verification path applies here.

---

## Known Limitations

| Limitation | Notes |
|-----------|-------|
| `ZS-JS-007`/`008`/`009` have no TS equivalents | Intentional scope decision — trivial to add later, same match patterns apply to TS's IR |
| Taint tracking is file-scoped, not function-scoped | Same documented ceiling as Python (Sprint 11), now applies to JS/TS too |
| No cross-language taint | A tainted value can't flow from a Python backend response into JS frontend code (not a realistic scenario for static analysis anyway) |
| `ZS-JS-006`/`ZS-TS-004` only cover `https.request` | Not `axios`, `node-fetch`, or other HTTP clients' equivalent options — same one-rule-per-callee constraint as Python's `requests.get`-only rule |
| C# parser remains a 1-line stub | Unchanged — separate Sprint 12 option (D) that wasn't chosen |
| SCA pom.xml/Gemfile.lock/gradle.lockfile still unsupported | Unchanged — separate Sprint 12 option (B) that wasn't chosen |
| No SCA caching/offline mode/backoff | Unchanged — separate Sprint 12 option (A) that wasn't chosen |

## Rule Coverage Roadmap

| Sprint | Focus | Result |
|--------|-------|--------|
| Sprint 11 ✅ | Python taint + OWASP 2025 | Python 14 → 23 rules |
| **Sprint 12 ✅** | JS/TS taint + OWASP 2025 | JS 5 → 10, TS 3 → 5 |
| Next (unpicked options from Sprint 12 planning) | SCA reliability (A), SCA ecosystem expansion (B), C# language support (D), Secrets expansion (E), monitor mode (G) | TBD — user to prioritize |
