# Sprint 11 Release Notes

## Summary

Sprint 11 delivers two improvements identified during a project status review and OWASP research pass:

1. **Intra-procedural taint tracking (Python)** — the injection rules that previously fired on *any* call to a sink function now only fire when the argument traces back to an untrusted source. This directly fixes the false-positive risk that `ZS-PY-004`, `ZS-PY-012`, and `ZS-PY-013` had explicitly documented in their own rule descriptions since earlier sprints ("this rule is a syntactic approximation").
2. **OWASP Top 10:2025 rule pack** — all existing Python rules re-tagged from the superseded 2021 edition to the official 2025 edition, plus 9 new rules covering the four categories that had zero coverage: A02 Security Misconfiguration, A07 Authentication Failures, A09 Security Logging & Alerting Failures, and A10 Mishandling of Exceptional Conditions (new category in 2025).

Python rule total: **14 → 23 rules**.

Version bumped to **v0.8.0**.

---

## New Feature: Taint Tracking (`internal/analyzer/taint`)

### Problem

Verified in code (not assumed): `internal/graph/graph.go`'s `CFG`/`DFG`/`CallGraph` types were empty `// TODO: Sprint 8` stubs, never implemented, and `analyzer.Analyze()` never touched them. `ZS-PY-004`'s rule YAML has said since it was written: *"this rule is a syntactic approximation... precision improves with taint analysis (Sprint 8)"* — never delivered until now.

### What was built

A lightweight, file-scoped, intra-procedural taint pass (`internal/analyzer/taint/taint.go`), run automatically as part of `analyzer.Analyze()`:

- **Sources**: `request.args/form/GET/POST/values`, `input(...)`, `sys.argv`, `os.environ.get(...)`.
- **Propagation**: `x = y`, `x = y + z`, `x = f(y)` — `x` is tainted if any identifier on the right-hand side is already tainted.
- **New engine filter**: `tainted_argument: true` — requires at least one call argument identifier to be in the tainted set.

**Known ceiling** (by design, not an oversight): taint is tracked per file, not per function. Two functions in the same file reusing a variable name could theoretically cross-contaminate taint state. Upgrade path: scope per function if this causes real false positives in practice.

### Rules updated

| Rule | Before | After |
|------|--------|-------|
| ZS-PY-004 (SQL string formatting) | Fired on any `execute(...)` call | Fires only when the argument is tainted |
| ZS-PY-012 (`subprocess.call`) | Fired on any call | Fires only when the argument is tainted |
| ZS-PY-013 (`os.popen`) | Fired on any call | Fires only when the argument is tainted |

### QA Test Cases

**TC-11.1 — Tainted argument fires ZS-PY-004**

```python
user_id = request.args.get('id')
query = "SELECT " + user_id
execute(query)
```
Expected: 1 finding, ZS-PY-004.

**TC-11.2 — Constant argument no longer fires ZS-PY-004 (false-positive fix)**

```python
query = "SELECT * FROM users"
execute(query)
```
Expected: 0 findings for ZS-PY-004.

**TC-11.3 — Tainted argument fires ZS-PY-012**

```python
cmd = request.args.get('cmd')
subprocess.call(cmd)
```
Expected: 1 finding, ZS-PY-012.

**TC-11.4 — Constant argument no longer fires ZS-PY-012**

```python
subprocess.call("ls -la")
```
Expected: 0 findings for ZS-PY-012.

---

## New Feature: OWASP Top 10:2025 Rule Pack

The 2025 edition (published at owasp.org/Top10/2025/) supersedes 2021. All 14 existing Python rules were re-tagged (`owasp:` field only — no detection logic changes) per the official category mapping, including two consolidations: SSRF rolled into A01 (Broken Access Control), and `ZS-PY-014` (CWE-377, insecure temp file) confirmed via the official CWE mapping to remain in A01.

### 9 new rules — covering the 4 previously-uncovered categories

| Rule | Category | Detects | Severity |
|------|----------|---------|----------|
| ZS-PY-016 | A02 Security Misconfiguration | `app.run(debug=True)` | high |
| ZS-PY-017 | A02 | Django `DEBUG = True` | high |
| ZS-PY-018 | A02 | `requests.get(verify=False)` | high |
| ZS-PY-019 | A02 | Django `ALLOWED_HOSTS` assignment (flags for review) | medium |
| ZS-PY-020 | A07 Authentication Failures | Hardcoded credential (`password`/`secret`/`api_key`/`token` = string literal) | high |
| ZS-PY-021 | A07 | `jwt.decode(verify=False)` | critical |
| ZS-PY-022 | A09 Security Logging & Alerting Failures | Sensitive-looking value passed to `logging.info()` | medium |
| ZS-PY-023 | A10 Mishandling of Exceptional Conditions (new category) | Bare `except:` clause | medium |
| ZS-PY-024 | A10 | Empty (`pass`-only) except handler | medium |

Three new engine matching capabilities were added to support these rules (all typed, none use raw regex-over-file-content — matching stays structural against the tree-sitter IR, consistent with the existing rule engine's design):

- `filters: [{kwarg: {name: ..., value_pattern: ...}}]` — matches a call's keyword argument by name and value (ZS-PY-016, 018, 021).
- `filters: [{argument_identifier_matches: "..."}]` — matches a call argument's identifier name by regex (ZS-PY-022).
- `filters: [{has_bare_except: true}]` / `filters: [{has_empty_except_handler: true}]` — inspect except-clause metadata newly captured by the Python IR builder (ZS-PY-023, 024).
- `rhs_literal` on `match:` — regex against an assignment's right-hand-side text (ZS-PY-017).

### QA Test Cases

**TC-11.5 — Flask debug mode**
```python
app.run(debug=True)
```
Expected: ZS-PY-016 finding, severity high.

**TC-11.6 — Django DEBUG**
```python
DEBUG = True
```
Expected: ZS-PY-017 finding, severity high.

**TC-11.7 — Hardcoded credential**
```python
password = "hunter2"
```
Expected: ZS-PY-020 finding, severity high.

**TC-11.8 — Bare except**
```python
try:
    do_thing()
except:
    pass
```
Expected: ZS-PY-023 finding (bare except) AND ZS-PY-024 finding (empty handler) — both conditions are true simultaneously here; test separately with a non-empty bare-except body and a typed-but-empty handler to isolate each rule.

**TC-11.9 — Typed except does not fire ZS-PY-023**
```python
try:
    do_thing()
except ValueError:
    log(e)
```
Expected: 0 findings for ZS-PY-023 or ZS-PY-024.

---

## Files Changed

| File | Change |
|------|--------|
| `internal/ir/node.go` | Added `NodeKindKeywordArg`, `ExceptHandler` struct |
| `internal/parser/python/builder.go` | Maps `keyword_argument` nodes + captures `kwarg_name`/`kwarg_value`; captures assignment `rhs` text; captures `except_handlers` metadata on `try` nodes |
| `internal/analyzer/taint/taint.go` | New package — file-scoped intra-procedural taint pass |
| `internal/analyzer/analyzer.go` | `AnalysisResult.TaintedVars`, wired into `Analyze()` |
| `internal/rules/rules.go` | `MatchPattern.RHSLiteral`; `Filter.TaintedArgument`, `Filter.Kwarg`, `Filter.ArgumentIdentifierMatches`, `Filter.HasBareExcept`, `Filter.HasEmptyExceptHandler` |
| `internal/rules/loader.go` | YAML parsing for all new match/filter fields |
| `internal/engine/engine.go` | Threads `TaintedVars` through matching; evaluates all 5 new filter types via a new `anyArgument`/`anyExceptHandler` helper pair |
| `internal/rules/data/python/ZS-PY-{001..015}.yaml` | Re-tagged `owasp:` field to 2025; `ZS-PY-004/012/013` add `tainted_argument` filter and drop the syntactic-approximation disclaimer |
| `internal/rules/data/python/ZS-PY-{016..024}.yaml` | 9 new rules |
| `internal/rules/loader_test.go` | Rule count assertion updated to ≥23 |
| `cmd/zerostrike/main.go` | Version `v0.8.0` |

---

## Test Results

Full no-CGo suite — **all packages pass**:

```
CGO_ENABLED=0 go test ./... -count=1

ok  internal/analyzer
ok  internal/analyzer/taint     (new package, 4 tests)
ok  internal/core
ok  internal/detector
ok  internal/engine             (+7 new: TaintedArgument, Kwarg, ArgumentIdentifierMatches,
                                  RHSLiteral, ExceptHandlerFilters)
ok  internal/findings
ok  internal/ir
ok  internal/pipeline
ok  internal/report/html
ok  internal/report/json
ok  internal/report/sarif
ok  internal/rules              (count assertion updated to ≥23)
ok  internal/scanner/sca
ok  internal/scanner/secrets
ok  internal/symboltable
ok  internal/walker
```

`go vet ./...` — clean.

**CGo-gated tests not locally verified**: this development environment has no GCC (`CGO_ENABLED=0` by default, consistent with prior sprints' documented Windows limitation). The following new/updated tests are written and syntax-checked (`gofmt -e`) but require the Linux CGo CI job to actually execute:

- `internal/parser/python/python_test.go` — `TestIRBuilder_KeywordArgument`, `TestIRBuilder_AssignmentRHS`, `TestIRBuilder_BareExcept`, `TestIRBuilder_TypedExceptNotBare`
- `internal/engine/integration_test.go` — 10 new integration tests covering taint tracking (ZS-PY-004/012) and the new rule pack (ZS-PY-016, 017, 020, 023, 024)

The except-clause metadata extraction (`buildExceptHandler` in `builder.go`) is implemented against standard tree-sitter-python grammar token names (`except`, `as`, `:`, `block`, `pass_statement`) rather than field names, specifically so it doesn't depend on assumptions about field bindings that couldn't be verified locally — but it still needs a real CGo run to confirm against the actual bundled grammar version.

---

## Known Limitations

| Limitation | Notes |
|-----------|-------|
| Taint tracking is file-scoped, not function-scoped | Documented ceiling in `taint.go`; upgrade if it causes false positives |
| Taint tracking is intra-procedural only | No cross-function taint (would need the CallGraph, which still doesn't exist) |
| `ZS-PY-004` only matches bare `execute(...)` calls | Pre-existing limitation (not introduced this sprint) — `cursor.execute(...)` style method calls use an attribute-qualified callee (`cursor.execute`) which the current rule's plain `execute` callee does not match. Flagged for a future sprint. |
| `ZS-PY-018` only covers `requests.get`, not post/put/delete | The engine requires one rule per exact callee string; add sibling rules if these show up in practice |
| `ZS-PY-022` only covers `logging.info`, not other levels or `print()` | Same one-rule-per-callee constraint |
| `ZS-PY-019` (ALLOWED_HOSTS) flags every assignment, not just wildcards | Cannot yet inspect list contents structurally; confidence set to `low` to reflect this |
| C# parser still a 1-line stub | Unchanged this sprint — out of scope |
| SCA pom.xml (Maven) / Gemfile.lock (Ruby) still unsupported | Unchanged this sprint — out of scope |

---

## Rule Coverage Roadmap

| Sprint | Focus | New Rules |
|--------|-------|-----------|
| Sprint 10 ✅ | Accuracy + TS | Python +5, JS +2, TS +3 |
| **Sprint 11 ✅** | Taint tracking + OWASP 2025 | Python +9 (23 total), 3 rules upgraded with taint filters |
| Sprint 12 | Fix `ZS-PY-004` callee matching; extend taint to JS/TS | TBD |
| Sprint 13 | C# parser + rules | C# +8 |
| Sprint 14 | SCA pom.xml / Gemfile.lock | Java + Ruby ecosystems |
