# Precision overhaul — context-aware matching

## Why

A scan of a Next.js + FastAPI application produced **1324 findings**, of which manual
verification against source confirmed **1321 were false positives (99.77%)**. An
open-source tool on the same codebase produced 30 findings, all actionable. One rule
accounted for 1301 findings — 98.3% of the report — and was wrong in every instance.

The engine was answering *"does this code look dangerous?"* rather than *"is this
reachable, deployed, attacker-influenced, and unguarded?"*.

The per-finding triage that established these numbers is held privately, since it
quotes the scanned application's source. Everything needed to reproduce the
behaviour is in `benchmark/corpus/fp/` and the tests listed below.

## Measured result

Against a reproduction of the reported patterns (400 pytest asserts, fixture
credentials, a guarded sentinel, a canary redaction test, an operator-configured
webhook, a browser API client, arrow-function timers, a guarded dynamic RegExp, and
the three genuine empty exception handlers):

| | Findings | Files scanned | Files skipped |
|---|---:|---:|---:|
| Before | 423 | 12 | 0 |
| After | **3** | 9 | 3 |

The 3 remaining are exactly the three genuine findings: two empty `except` handlers and
one empty `catch` block. Every false-positive class in the triage report is gone.

Accuracy gate across the whole corpus: **TP=460 FP=0 FN=0, precision 100%, recall 100%**
(baseline before this work: TP=461, the one lost TP being the retired rule's own case).

## What changed

### 1. File-role classification (`internal/walker/role.go`)

`ClassifyRole` marks tests, fixtures, mocks and test data by path segment
(`tests/`, `__tests__/`, `testdata/`, `fixtures/`, `mocks/`, `spec/`) and by file name
(`conftest.py`, `test_*.py`, `*_test.go`, `*.spec.ts`, `*Test.java`, `*Tests.cs`, …).
Those files are dropped before any scanner parses them, and counted in the report's
`FilesSkipped`.

`--include-tests` scans them anyway. Verified as a true round-trip: the suppressed
findings return under the flag and none are lost, so they are suppressed by role rather
than lost to a filtering bug.

Segment matching is whole-component, so `pentest/`, `latest/`, `contest/` and
`attestation/` are unaffected.

### 2. Retired-rule enforcement, and `ZS-PY-009` retired

`lifecycle` was validated from the start and read by nothing — a rule marked `retired`
still loaded and still fired. `engine.BuildIndex` now skips retired rules.

`ZS-PY-009` (*assert Used for Security Check*) is retired. It matched the `assert`
keyword with **no filters at all**: 1300 of its 1301 findings were pytest assertions and
the last was a type-narrowing `assert x is not None`. It is retired rather than repaired
because CWE-617's premise is that asserts vanish in production, which requires
`python -O` or `PYTHONOPTIMIZE` — a launch condition the engine cannot observe, so the
rule could never establish its own precondition.

> **What this gives up:** a genuine `assert user.is_admin()` access-control check is no
> longer reported. This was the rule's corpus fixture and it was deleted with the rule.
> Recorded here so it is not later rediscovered as a regression. `ZS-PHP-021`
> (taint-gated `assert`, CWE-95) is a different rule and is unaffected.

### 3. Taint provenance tiering (`taint.Result.Weak`)

The root cause of three of the six false-positive classes was one line: every function
parameter is seeded tainted. That is deliberate and load-bearing for recall — a handler
extracts the value and a helper does the dangerous thing with it — but on its own it made
`setTimeout(cb, delay)`, `fetch(url)` and `new RegExp(pattern)` fire on any ordinary
helper that takes an argument.

Taint is now tiered. Parameter-seeded taint is **weak**; taint from a matched source
pattern or a function summary is **strong**, and weakness follows the propagation edge.
The new `require_real_source` filter demands strong taint, and is set only on sinks that
are noisy under parameter seeding: `fetch`, `RegExp`, `setTimeout`, `setInterval`,
`urlopen`. SQL, command-injection and path-traversal rules keep parameter taint, where it
is the whole point.

### 4. `argument_kind_not_at` filter

The `setTimeout` rule's own message says *"string arguments are eval'd; pass a function
instead"* — and it fired on call sites that pass a function. It flagged its own
remediation, which would false-positive on essentially every React codebase.

The new filter suppresses a match when a given positional argument is itself one of the
named IR node kinds. Applied as `index: 0, kinds: [function_def]`, since `arrow_function`
lowers to `NodeKindFunction`. Expressed negatively on purpose: a bare identifier holding
a string is a legitimate hit, so an allowlist of permitted kinds would exclude it. The
kind check is non-recursive — a descendant walk would find almost any kind inside a
callback body and never exclude anything.

The validator rejects an unknown node kind here, so a typo fails at load time instead of
becoming a filter that silently matches nothing.

### 5. Inline suppressions (`internal/suppress`)

Nothing honoured `nosemgrep` / `nosec` / `noqa` / `zs-ignore` before this. Now
recognised on the flagged line, the line above, or anywhere within a finding's reported
span — the span matters because a `kind: try` rule anchors at `try:` while the annotation
belongs on the `except` clause several lines down.

**Rule-ID semantics are strict:** a marker followed by identifiers suppresses only when
one of them is a ZeroStrike rule ID. A foreign tool's code does not suppress a ZeroStrike
finding — `# noqa: BLE001` is a ruff annotation, and treating it as blanket permission
would have hidden all three genuine empty-handler findings. A bare marker is blanket
suppression. Markers are only honoured inside a comment, so a string literal containing
"noqa" suppresses nothing.

### 6. Secret context filters, generic detectors only

A `generic` flag now distinguishes detectors that match by surrounding syntax
(`password = "..."`, `"token": "..."`, credential-bearing URIs) from provider-shaped ones
(`AKIA…`, `ghp_…`, PEM blocks). Placeholder vocabulary, RFC 2606 reserved hosts, and
assertion-context checks apply **only** to generic detectors.

The split is the point: AWS's own documentation key is literally
`AKIAIOSFODNN7EXAMPLE`, so rejecting values containing "EXAMPLE" would have disabled a
real detector.

`localhost` / `127.0.0.1` are deliberately **not** treated as example hosts: a committed
`mongodb://admin:secretpass123@localhost` is a real hardcoded credential, and the host
being local says nothing about whether the password is.

### 7. Guarded sentinels (YAML only)

The clearest miss in the report: `INSECURE_JWT_SECRET` was flagged HIGH, when the literal
exists *so that* a start-up guard can recognise it and refuse to boot. Deleting it would
have removed the check that makes the deployment safe.

All seven `Hardcoded Credential` rules gained a `not` filter on an
`INSECURE_|PLACEHOLDER|CHANGEME|DEV_ONLY|EXAMPLE|DUMMY|FAKE|SAMPLE|DEFAULT_` prefix. No Go
code — `Filter.Not` and `lhs_identifier` already existed. Matched by naming convention
rather than by proving the guard exists: confirming the comparison needs cross-function
analysis, and a value shouting `INSECURE_` at the reader is already a deliberate signal.

### 8. OWASP corrections

`CWE-390` empty-handler rules claimed `A10:2025` (SSRF), which rendered
*"Server-Side Request Forgery — FAIL, 3 findings"* on a report containing zero SSRF. Now
`A09:2025` (Logging & Monitoring Failures) in `ZS-PY-024`, `ZS-JS-010`, `ZS-TS-005`.
`ZS-PY-009`'s bogus `A06:2025` — which produced *"Vulnerable and Outdated Components —
FAIL, 1301 findings"* on a scan that analysed no dependencies — went with the rule.

### 9. Cross-engine credential dedup

The SAST and secrets engines reported the same literal independently, so one line became
two findings and `config.py:9` became four rows. Credential-family findings now dedup on
`(class, file, line)`, with the second engine's rule ID preserved in
`Metadata["also_reported_by"]` rather than discarded — a corroborated finding should not
look like a single-engine one.

### 10. `benchmark/corpus/fp/` — a precision gate

The accuracy gate only had vulnerable and clean fixtures, so `--max-fp 0` measured
nothing about the patterns that caused these 1321 findings. Precision had no fixtures at
all, which is how a rule that fires on every `assert` keyword shipped.

Seven cases, all `expect: []`: pytest asserts in a test path, an arrow-function timer, a
constant-URL fetch, a guarded RegExp, a guarded sentinel, a canary redaction test, and a
`zs-ignore`-annotated handler. **This corpus found two surviving false positives on its
first run** and both were fixed.

`include_tests` is deliberately unset here, so the corpus exercises role filtering for
real.

### 11. Cache invalidation (`version.MatchSemanticsRevision`)

`HashRuleSet` hashes only rule YAML, and `version.Version` is build-injected and stays
`"dev"` for every local and CI build — so two binaries with materially different matching
semantics were indistinguishable to the finding cache, and the first scan after an upgrade
served pre-change findings from disk. `version.CacheKey()` now pairs the release version
with a hand-bumped semantics revision; an `EngineVersion` mismatch wipes `findings/` and
`ir/`.

**Bump `MatchSemanticsRevision` whenever a Go-side change can alter findings for
byte-identical source.**

## Benchmark corpus changes

Two fixtures changed, both because a rule's contract changed:

- **`python/cases/vuln_assert.py` — deleted** with `ZS-PY-009`.
- **`python/cases/vuln_urlopen.py` — rewritten.** `ZS-PY-015` had no filter: every
  `urlopen` call was a finding regardless of its argument, which is what reported an
  operator-configured webhook URL as SSRF. Its meaning is deliberately narrowed from
  "urlopen is used" to "urlopen is called with an untrusted target", so the fixture now
  carries a real source. This is a semantic rule change that required the fixture to
  follow, **not** a benchmark tweak to make the gate pass.
  *Consequence accepted:* `urlopen(constant)` is no longer reported. If that hardening
  signal is wanted back, it belongs in a separate INFO-severity rule.
- **`go/manifest.yaml`** gained `include_tests: true`. The Go corpus must live under
  `testdata/` so `go build ./...` skips it, and `testdata/` is a path real users need
  suppressed. Set per-manifest, not globally, so the `fp/` corpus still tests the filter.
  Verified load-bearing: removing it drops TP 461→415 with FN=46.

## Out of scope

- **Execution-context classification** (browser vs server, CWE-918 scoping). Provenance
  tiering removed the SSRF false positives it was proposed for. Revisit only if a
  server-context false positive appears that tiering misses.
- **Overall risk rating.** No risk computation exists in this repository; severity is
  copied verbatim from rule YAML. `Overall Risk: HIGH` is produced portal-side.
- **Collapsing repeated findings into occurrence counts.** `--group-by rule` already does
  this.
- **Narrowing parameter seeding itself.** Tiering achieves the precision gain without
  touching what the in-code comment identifies as load-bearing for recall.

## Observation, not addressed

`ZS-PY-008` (*open() with Potentially User-Controlled Path*) fires on `open(path)` where
`path` is a plain function parameter — the same parameter-only-taint class as the fixed
rules. It was not in the triage report and path traversal is a case where parameter taint
is arguably legitimate, so it was left alone rather than widened into scope. Worth a
decision if it shows up as noise on a real target.

## Verification performed

- `go build ./...`, `go vet ./...` clean; all touched files `gofmt`-clean.
- `go test ./...` passes.
- `go test -race ./internal/engine/ ./internal/pipeline/` passes — this change threads a
  new map through the shared rule index, and `engine.go` documents a prior race there
  where appending to a slice read out of `RuleIndex` caused nondeterministic missed
  findings.
- Accuracy gate: `TP=460 FP=0 FN=0` at `--min-recall 0.90 --max-fp 0`.
- 12 new integration tests assert every precision filter in **both** directions: the
  false positive disappears *and* the genuine finding still fires.
- `--workers 1` and `--workers 4` produce identical findings.

**Not performed:** a scan of the original target repository, which is not present in this
workspace. The before/after above is a faithful reproduction of the patterns documented in
the private triage, not the real codebase. Re-run against the real target to confirm
the 3-finding result before treating it as settled.
