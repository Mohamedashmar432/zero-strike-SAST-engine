# ZeroStrike Accuracy Benchmark Corpus

A scored corpus of known-labeled fixtures used by `cmd/zerostrike-bench` to
measure precision/recall across every scanning modality (SAST, secrets, SCA,
framework misconfiguration), replacing prose-based QA with numbers that can
be diffed release over release.

## Layout

```
corpus/
  python/  js/  ts/  csharp/  go/  php/   manifest.yaml + cases/*   (SAST)
  secrets/                    manifest.yaml + cases/*.txt
  sca/                        manifest.yaml + cases/{npm,go}-{vuln,clean}/
  framework/                  manifest.yaml + cases/{django,express,cors,laravel}/
```

Fixtures here are **copied**, not symlinked or referenced, from
`testdata/`. `testdata/` fixtures may change for unrelated unit-test
reasons; this corpus needs frozen, manifest-labeled content whose only
reason to change is a deliberate accuracy update.

## Manifest schema (`manifest.yaml`, one per corpus subdirectory)

```yaml
version: "1"
cases:
  - file: cases/vuln_eval.py
    language: python                 # optional, used for per-language recall
    expect:
      - rule_id: ZS-PY-001
        min_count: 1
  - file: cases/clean.py
    language: python
    expect: []                       # explicit true negative
  - file: cases/npm-vuln/package-lock.json
    ecosystem: npm
    expect:
      - dependency: {package: lodash, ecosystem: npm}   # SCA matches by (ecosystem, package), not rule_id — every SCA finding shares RuleID=ZS-SCA-001
```

`expect: []` is required (not inferred from a "clean" filename) so every
case is self-describing.

## Adding a case

1. Add the fixture file under `cases/`.
2. Add a manifest entry declaring what should (or, for a clean fixture,
   should NOT) fire. Verify the expectation by reading the actual rule
   YAML/detector logic — do not guess from the filename. A case with a
   wrong expectation makes the accuracy gate lie.
3. Re-run `go run ./cmd/zerostrike-bench --corpus benchmark/corpus` and
   confirm the new case scores as expected before committing.

## Known v1 scope gaps (not silently dropped — tracked here)

- **Python taint-gated rules excluded** (`ZS-PY-004`, `ZS-PY-012`,
  `ZS-PY-013`): their fixtures pass a value traced from a bare function
  parameter, which the current same-file taint model (`internal/analyzer/taint/patterns.go`)
  does not treat as tainted (only specific sources like `request.args`,
  `os.environ.get`, etc. do). Confirming these would fire requires a
  CGo-enabled local run this environment doesn't have (no `gcc`); adding
  them is a follow-up once verified.
- **`testdata/python/vuln_assert.py` excluded**: its own file comment
  states it does not fire ("tree-sitter emits assert_statement, not
  call") — a documented, pre-existing false negative, not something this
  corpus should assert as a true positive.
- **No TypeScript fixtures existed before this sprint** — `corpus/ts/`
  cases were written fresh, mirroring the exact source/sink shape proven
  by `internal/engine/integration_javascript_test.go`'s TS cases.
- **SCA covers npm and Go only** — pip/Maven/Gemfile ecosystem cases are
  a Sprint 18 (SCA ecosystem expansion) follow-up.
- **SCA cases depend on the live OSV API** (same as `scan-e2e`'s
  dvna/dvpwa scans). A transient OSV outage can make SCA recall look like
  a regression when it isn't — see `docs/roadmap/ARCHITECTURE-DECISIONS.md`
  and the Sprint 15+16 release notes for the accepted risk.

None of these gaps are covered by the `--min-recall`/`--max-fp` CI gate's
current scope; they're listed here so "the corpus passed" isn't read as
"the corpus is exhaustive."
