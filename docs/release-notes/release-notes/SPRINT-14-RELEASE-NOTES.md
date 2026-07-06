# Sprint 14 Release Notes

## Summary

Sprint 14 onboards two new languages — **Go** and **PHP** — using Sprint 13's
`internal/langreg` registration pattern, proving it scales to two languages
at once with no new exceptions in `sast.go`, `embed.go`, or `scanner.go`.
Both ship with a 4-file parser package (tree-sitter grammar wrapper, IR
builder, `langreg` registration, doc stub), a 5-rule pack, per-language
taint source/sanitizer patterns, and integration tests. Version bumps to
**v0.11.0**.

---

## Go

`.go` files are detected, parsed via `github.com/smacker/go-tree-sitter/golang`,
converted to IR by `internal/parser/golang/builder.go`, and scanned through
the Sprint 13 registry — no special-casing anywhere. `ir.NodeKind` gained
three new values for Go's paradigm gap versus Python/JS/TS/C#: `NodeKindSwitch`,
`NodeKindSelect`, `NodeKindDefer`. Grammar node-type and field names were
verified against the pinned grammar's `parser.c` symbol table rather than
assumed.

### Rule pack

| Rule | Finding | Match | CWE / OWASP |
|---|---|---|---|
| ZS-GO-001 | Command injection | `exec.Command(...)` + tainted argument | CWE-78 / A05:2025 |
| ZS-GO-002 | SQL injection | `db.Query(...)` + tainted argument | CWE-89 / A05:2025 |
| ZS-GO-003 | Path traversal | `os.Open(...)` + tainted argument | CWE-22 / A01:2025 |
| ZS-GO-004 | Weak crypto | `md5.New()` | CWE-327 / A04:2025 |
| ZS-GO-005 | Hardcoded credential | credential-named var := string literal | CWE-798 / A07:2025 |

**Known limitation (ZS-GO-002):** `db.Query` is a receiver-variable method
call, not a package-qualified function, so the rule only fires when the
`*sql.DB`/`*sql.Tx` variable is conventionally named `db` — same shape as
Sprint 13's `BinaryFormatter`-constructor caveat. A companion rule for other
receiver names (`tx`, `conn`) is a follow-up, not blocking this sprint.

### Taint

New `goPatterns` in `internal/analyzer/taint/patterns.go`: sources
`os.Args`, `r.URL.Query()`/`FormValue`/`PostFormValue`, `os.Getenv`;
sanitizers `html.EscapeString`, `template.HTMLEscapeString`.

---

## PHP

`.php` files are detected, parsed via `github.com/smacker/go-tree-sitter/php`,
converted to IR by `internal/parser/php/builder.go`, and scanned through the
same registry.

### Rule pack

| Rule | Finding | Match | CWE / OWASP |
|---|---|---|---|
| ZS-PHP-001 | Command injection | `system(...)` + tainted argument | CWE-78 / A05:2025 |
| ZS-PHP-002 | SQL injection | `mysqli_query(...)` + tainted argument | CWE-89 / A05:2025 |
| ZS-PHP-003 | Insecure deserialization | `unserialize(...)` (any use is the risk) | CWE-502 / A08:2025 |
| ZS-PHP-004 | XSS sink | `echo` of a tainted value | CWE-79 / A05:2025 |
| ZS-PHP-005 | Hardcoded credential | credential-named var = string literal | CWE-798 / A07:2025 |

**Design decision — `echo` as a synthetic call node.** `echo` is a language
construct, not a call, so it doesn't fit the engine's `NodeKindCall` +
`TaintedArgument` filter without a new statement-kind match path in
`internal/engine`. Rather than extend the engine, `echo_statement` is built
as a `NodeKindCall` with a synthetic `"echo"` identifier followed by the
echoed expression(s) as arguments — the exact shape a real `echo(...)` call
would have. This reuses `TaintedArgument`/`calleeText` unchanged.
`// ponytail: synthetic-call shape for echo, revisit only if PHP needs a
true statement-kind match in the rule engine.`

**Known limitations:** `exec()`/`shell_exec()` (command injection) and the
OO `mysqli`/`PDO` query forms (SQL injection) are equivalent sinks left as
companion-rule follow-ups — same one-callee-per-rule precedent as Sprint
13's MD5/SHA1 split.

### Taint

New `phpPatterns`: source `$_GET`/`$_POST`/`$_REQUEST`/`$_COOKIE`/`$_SERVER`;
sanitizers `htmlspecialchars`, `htmlentities`, `escapeshellarg`.

---

## Onboarding-time note (Wave 2 baseline)

Go took longer than PHP, as expected going in (it's the paradigm-distant
language). The bulk of the extra time was: (1) confirming real tree-sitter
node/field names against the pinned grammar's `parser.c` symbol table rather
than guessing (`field_identifier`/`package_identifier` as distinct alias
types from plain `identifier` was the one non-obvious finding — missing
either would have silently broken dotted-callee resolution for
`exec.Command`/`os.Open`/`md5.New`); (2) handling Go's grouped-parameter
form (`func f(a, b string)`, multiple names sharing one type) and multi-value
returns, neither of which exist in Python/JS/TS/C#. PHP was cheaper as
predicted — closer to the existing dynamic-language shape — except for one
genuine surprise: `echo` has no call-shaped grammar node, which needed the
synthetic-call design decision above rather than a simple grammar mapping.
Net takeaway for Sprint 17 (Java + Ruby): budget extra time whenever a
target language's grammar uses alias/synthetic node types for identifiers,
and treat "does every sink read as a call node" as a checklist item before
committing to a rule's `match.kind`.

---

## Files Changed

| File | Change |
|---|---|
| `internal/core/language.go` | `LangGo`, `LangPHP` added |
| `internal/detector/extension.go` | `.go` → `LangGo`, `.php` → `LangPHP` |
| `internal/ir/node.go` | `NodeKindSwitch`, `NodeKindSelect`, `NodeKindDefer` added |
| `internal/parser/golang/{golang,builder,register,doc}.go` | New — Go parser/builder/registration |
| `internal/parser/php/{php,builder,register,doc}.go` | New — PHP parser/builder/registration |
| `internal/rules/data/go/ZS-GO-00{1..5}.yaml` | New — 5-rule Go pack |
| `internal/rules/data/php/ZS-PHP-00{1..5}.yaml` | New — 5-rule PHP pack |
| `internal/rules/embed.go` | `data/go`, `data/php` embedded and added to `RuleDirs` |
| `internal/rules/loader_go_test.go`, `loader_php_test.go` | New |
| `internal/analyzer/taint/patterns.go` | `goPatterns`, `phpPatterns` added |
| `internal/analyzer/taint/taint_test.go` | +2 tests (Go/PHP source-taints-variable) |
| `internal/engine/integration_go_test.go`, `integration_php_test.go` | New — 6 cases each (cgo) |
| `testdata/go/*.go`, `testdata/php/*.php` | New — 5 vuln fixtures + 1 clean fixture each |
| `cmd/zerostrike/main.go` | Blank imports for golang/php; version → `v0.11.0` |
| `internal/scanner/sast/sast.go` | Blank imports for golang/php |
| `.github/workflows/ci.yml` | `scan-e2e` scans `testdata/go/` and `testdata/php/`, uploads their reports |

---

## Test Results

`CGO_ENABLED=0 go test ./... -count=1` — **all packages pass**;
`CGO_ENABLED=0 go build ./...` and `go vet ./...` clean. This covers
`internal/langreg`, the new `loader_go_test.go`/`loader_php_test.go` (rule
YAML parses and validates without cgo), `internal/analyzer/taint` (including
the two new Go/PHP source tests), and the generic `internal/pipeline`
fail-fast validation test.

**CGo-gated code not verified locally** — no `gcc` in this dev environment,
same constraint as Sprints 11–13. The Go/PHP parser/builder packages, their
`register.go` files, and `integration_go_test.go`/`integration_php_test.go`
were verified via `gofmt -e` syntax checking and manual review against the
pinned grammars' confirmed node-type/field tables (`smacker/go-tree-sitter`'s
`golang/parser.c` and `php/parser.c` symbol tables), plus `go list` confirming
both grammar import paths resolve. The `test / ubuntu (CGo)` and
`scan-e2e / ubuntu-cgo` CI jobs are the authoritative verification, as in
prior sprints.

---

## Known Limitations

- ZS-GO-002 only matches the `db` receiver-variable convention (see above).
- ZS-PHP-001/002 cover one callee each; `exec`/`shell_exec` and OO
  `mysqli`/`PDO` query forms are companion-rule follow-ups.
- Taint remains file-scoped and flow-insensitive for Go/PHP, same ceiling
  documented in Sprint 13 for the existing languages.
- **CGo path not compiled locally** (see Test Results).
