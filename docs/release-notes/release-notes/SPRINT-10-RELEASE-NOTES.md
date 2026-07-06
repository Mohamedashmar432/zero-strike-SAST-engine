# Sprint 10 Release Notes

## Summary

Sprint 10 delivers three improvements that directly address findings from the Sprint 9 QA review:

1. **Walker false-positive fix** — `static/`, `assets/`, and other common vendored-asset directories are now skipped by default, eliminating jQuery/minified-JS false positives from Python projects. A new `--exclude-dir` CLI flag lets users add project-specific exclusions.
2. **Rule coverage expansion** — 10 new SAST rules across three languages: Python (+5), JavaScript (+2), TypeScript (+3).
3. **TypeScript parser** — Full tree-sitter-based TypeScript/TSX support. ZeroStrike now analyses `.ts` and `.tsx` files for the same vulnerability patterns it detects in JavaScript.

Version bumped to **v0.7.0**.

---

## New Feature: Walker Directory Exclusions

### Problem
The sprint 9 QA scan of dvpwa (Python/aiohttp) found `eval()` and `innerHTML` findings inside `static/jquery.min.js` — a vendored asset, not application code. The walker was not skipping `static/` by default.

### Fix
`internal/walker/filter.go` — `hardcodedSkipDirs` extended with 11 new entries:

| Category | New skip dirs |
|----------|--------------|
| Static assets / frontend | `static`, `assets`, `public`, `media` |
| Test coverage / caches | `htmlcov`, `coverage`, `.tox`, `.pytest_cache`, `.mypy_cache`, `.ruff_cache` |
| Framework scaffolding | `migrations` |

Combined with existing skips (`vendor`, `node_modules`, `dist`, `build`, `.git`, etc.) the default list now covers the most common sources of false positives in Python/JS projects.

### New `--exclude-dir` CLI flag

```bash
# Skip project-specific generated/vendored dirs
zerostrike scan --exclude-dir gen --exclude-dir proto_out --format json ./src
```

`--exclude-dir` is repeatable (or comma-separated). The names are matched against **directory base names** (not full paths) at every depth.

### QA Test Cases

**TC-10.1 — static/ is skipped by default**

```bash
# Create a minimal tree with static/jquery.min.js and app.py
zerostrike scan --format json /path/to/dvpwa | grep -c '"static'
# Expected: 0  (no findings from static/)
```

**TC-10.2 — --exclude-dir skips custom directory**

```bash
zerostrike scan --exclude-dir templates --format json ./src
# Verify findings do not reference files inside templates/
```

**TC-10.3 — Existing skip dirs still work**

```bash
# Project with node_modules/ — no findings from inside it
zerostrike scan --format json /path/to/dvna | python -m json.tool | grep "node_modules"
# Expected: no output
```

---

## New Feature: Python +5 SAST Rules

| Rule | Name | Callee | Severity | CWE |
|------|------|--------|----------|-----|
| ZS-PY-011 | Weak Hash (SHA1) | `hashlib.sha1` | medium | CWE-327 |
| ZS-PY-012 | subprocess.call() | `subprocess.call` | high | CWE-78 |
| ZS-PY-013 | os.popen() | `os.popen` | high | CWE-78 |
| ZS-PY-014 | tempfile.mktemp() | `tempfile.mktemp` | medium | CWE-377 |
| ZS-PY-015 | urllib SSRF Entry Point | `urllib.request.urlopen` | medium | CWE-918 |

Python rule total: **10 → 15 rules**.

### QA Test Cases

**TC-10.4 — ZS-PY-011 fires on hashlib.sha1**

Create `test_sha1.py`:
```python
import hashlib
digest = hashlib.sha1(b"password").hexdigest()
```

```bash
zerostrike scan --format json . | jq '.Findings[] | select(.RuleID=="ZS-PY-011")'
# Expected: 1 finding, severity medium, category cryptography
```

**TC-10.5 — ZS-PY-012 fires on subprocess.call**

Create `test_call.py`:
```python
import subprocess
subprocess.call("ls -la", shell=True)
```

```bash
zerostrike scan --format json . | jq '.Findings[] | select(.RuleID=="ZS-PY-012")'
# Expected: 1 finding, severity high
```

**TC-10.6 — ZS-PY-013 fires on os.popen**

```python
import os
result = os.popen("whoami").read()
```

Expected: ZS-PY-013 finding, severity high.

**TC-10.7 — ZS-PY-014 fires on tempfile.mktemp**

```python
import tempfile
path = tempfile.mktemp()
```

Expected: ZS-PY-014 finding, severity medium, category race-condition.

**TC-10.8 — ZS-PY-015 fires on urllib.request.urlopen**

```python
import urllib.request
urllib.request.urlopen(user_url)
```

Expected: ZS-PY-015 finding, severity medium, category ssrf.

---

## New Feature: JavaScript +2 SAST Rules

| Rule | Name | Match | Severity | CWE |
|------|------|-------|----------|-----|
| ZS-JS-004 | Function() Constructor | `kind: call, callee: Function` | high | CWE-95 |
| ZS-JS-005 | outerHTML Assignment | `kind: assignment, lhs_identifier: outerHTML` | high | CWE-79 |

JavaScript rule total: **3 → 5 rules**.

### QA Test Cases

**TC-10.9 — ZS-JS-004 fires on new Function()**

Create `test_func.js`:
```javascript
const fn = new Function("return " + userInput);
fn();
```

Expected: ZS-JS-004 finding, category injection, severity high.

**TC-10.10 — ZS-JS-005 fires on outerHTML assignment**

```javascript
element.outerHTML = userInput;
```

Expected: ZS-JS-005 finding, category xss, severity high.

---

## New Feature: TypeScript Parser + 3 Rules

### Parser

`internal/parser/typescript/typescript.go` implements the `parser.Parser` interface using `github.com/smacker/go-tree-sitter/typescript/typescript`. TypeScript is a strict superset of JavaScript — all JS AST node types are handled identically; TS-specific nodes (`interface_declaration`, `type_alias_declaration`, `decorator`, `as_expression`, etc.) map to `NodeKindUnknown` and are traversed but produce no findings until taint analysis lands.

`internal/parser/typescript/builder.go` — IR builder (copy of JS builder extended with 10 TS-specific `mapKind()` entries).

The SAST scanner auto-detects `.ts` and `.tsx` files (already in `detector/extension.go`) and routes them through the TypeScript builder.

| Rule | Name | Match | Severity |
|------|------|-------|----------|
| ZS-TS-001 | eval() Usage | `kind: call, callee: eval` | high |
| ZS-TS-002 | innerHTML Assignment | `kind: assignment, lhs_identifier: innerHTML` | high |
| ZS-TS-003 | document.write() | `kind: call, callee: document.write` | high |

### QA Test Cases

**TC-10.11 — TypeScript file is scanned (CGo required — Linux CI)**

Create `app.ts`:
```typescript
const result = eval(userInput);
```

```bash
CGO_ENABLED=1 zerostrike scan --format json . | jq '.Findings[] | select(.RuleID=="ZS-TS-001")'
# Expected: 1 finding in app.ts
```

**TC-10.12 — TSX file is scanned**

Create `Component.tsx`:
```tsx
function App({ html }: { html: string }) {
  const el = document.getElementById("root")!;
  el.innerHTML = html;
}
```

Expected: ZS-TS-002 finding (innerHTML) in Component.tsx.

**TC-10.13 — TypeScript-specific syntax does not crash the parser**

Create `typed.ts`:
```typescript
interface User { name: string; }
type ID = string | number;
const greet = (u: User): string => `Hello ${u.name}`;
```

Expected: scan completes with 0 findings and 0 diagnostics (no parse errors).

**TC-10.14 — TypeScript parser unit tests pass (CGo)**

```bash
CGO_ENABLED=1 go test ./internal/parser/typescript/... -v
# Expected: TestTypeScriptParser_Parse PASS, TestTypeScriptBuilder_Build PASS
```

---

## Files Changed

| File | Change |
|------|--------|
| `internal/walker/filter.go` | `hardcodedSkipDirs` extended (+11 dirs: static, assets, public, media, htmlcov, coverage, .tox, .pytest_cache, .mypy_cache, .ruff_cache, migrations) |
| `internal/pipeline/config.go` | Added `ExcludeDirs []string` field |
| `internal/pipeline/scanner.go` | Pass `ExcludeDirs` to walker `Options`; added `"data/ts"` to `loadAllRules()` |
| `cmd/zerostrike/scan.go` | Added `--exclude-dir` flag wired to `ScanConfig.ExcludeDirs` |
| `internal/rules/data/python/ZS-PY-011..015.yaml` | 5 new Python rules |
| `internal/rules/data/js/ZS-JS-004..005.yaml` | 2 new JS rules |
| `internal/parser/typescript/typescript.go` | TypeScript tree-sitter parser |
| `internal/parser/typescript/builder.go` | TypeScript IR builder |
| `internal/parser/typescript/typescript_test.go` | 2 CGo-gated parser tests |
| `internal/scanner/sast/sast.go` | Added `case core.LangTypeScript` to `buildIR()` |
| `internal/rules/embed.go` | Added `data/ts/*.yaml` to embed directive |
| `internal/rules/data/ts/ZS-TS-001..003.yaml` | 3 new TypeScript rules |
| `internal/rules/loader_test.go` | Updated Python rule count assertion (≥14) |
| `internal/rules/loader_javascript_test.go` | Updated JS count (≥5); added `TestLoader_TSRulesLoad` |
| `cmd/zerostrike/main.go` | Version `v0.7.0` |

---

## Test Results

Full no-CGo suite — **all packages pass**:

```
CGO_ENABLED=0 go test ./... -count=1

ok  internal/analyzer
ok  internal/core
ok  internal/detector
ok  internal/engine
ok  internal/findings
ok  internal/ir
ok  internal/pipeline
ok  internal/report/html
ok  internal/report/json
ok  internal/report/sarif
ok  internal/rules          (+1 new: TestLoader_TSRulesLoad; counts updated)
ok  internal/scanner/sca
ok  internal/scanner/secrets
ok  internal/symboltable
ok  internal/walker          (+2 new: TestWalk_SkipsStaticDir, TestWalk_ExcludeDirOption)
```

CGo-gated tests (`internal/parser/typescript/`) require GCC and run in the `ubuntu-cgo` CI matrix job.

---

## Known Limitations

| Limitation | Sprint |
|-----------|--------|
| C# parser not yet implemented | Sprint 11 |
| No taint/dataflow analysis — rules are syntactic approximations | Sprint 12 |
| SCA pom.xml (Maven) and Gemfile.lock (Ruby) not supported | Sprint 11/14 |
| TS-specific syntax (interfaces, decorators, `as` casts) produces no findings | Sprint 12 (taint) |

---

## Rule Coverage Roadmap

| Sprint | Focus | New Rules |
|--------|-------|-----------|
| **Sprint 10** ✅ | Accuracy + TS | Python +5, JS +2, TS +3 |
| Sprint 11 | C# parser + rules | C# +8 |
| Sprint 12 | Taint/dataflow analysis | Refines existing rules, reduces false positives |
| Sprint 13 | Secrets detector expansion | Secrets +10 |
| Sprint 14 | SCA pom.xml / Gemfile.lock | Java + Ruby ecosystems |
