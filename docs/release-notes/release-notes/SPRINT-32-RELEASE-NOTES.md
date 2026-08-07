# Sprint 32 — Differential coverage measurement, and the correctness bug it exposed

**v0.26.0**

This sprint set out to build an external measurement of detection coverage,
because the internal one had stopped being informative. It found a correctness
bug on the way there.

---

## 1. The number that started this was not a measurement

The committed `baseline.json` reported **22.64% recall with 41 false
negatives**, and that figure was being used as evidence of a large SAST
coverage gap.

It was a `CGO_ENABLED=0` artifact. Every tree-sitter parser sits behind
`//go:build cgo`, so a no-CGo binary registers zero languages: every AST rule
matches nothing while the pure-Go secrets, SCA, and framework scanners keep
passing. That is exactly the shape the file reported — SAST 0/41, secrets 5/5,
SCA 3/3, config 4/4. Its 12 TP + 41 FN = 53 expectations is precisely the
Sprint 21-22 corpus, frozen since 2026-07-08 while the corpus grew to 450.

**This is the third time this failure has produced a wrong conclusion** —
Sprint 23's "1.4% detection", Sprint 28's QA report, and now a committed
artifact that went unchallenged for roughly ten sprints. It is now
structurally impossible: `zerostrike-bench` exits 2 rather than scoring when
no parser is registered. A partial scan is useful; a partial score is just a
wrong number.

The C toolchain that its absence was blamed on was installed the whole time,
just off `PATH`. `go env -w CGO_ENABLED=1` plus an absolute `CC` now makes a
plain `go build` a full CGo build in any shell.

## 2. The real bug: the matcher mutated its own shared rule index

`engine.Match` seeded each node's candidate list directly from the shared
index and appended to it:

```go
candidates := mc.Index.byKind[n.Kind]                        // aliases the index
candidates = append(candidates, mc.Index.byCallee[text]...)  // spare cap -> writes INTO it
```

That slice aliases the index's own backing array. When it had spare capacity —
`byKind[call]` holds 3 rules with cap 4, so exactly one spare slot — the append
wrote into the index itself. Every file in a scan matches against that one
index across `runtime.NumCPU()` workers, so goroutines overwrote each other's
candidate lists and rules were evaluated against the wrong nodes.

Twelve identical scans of the same twelve fixtures:

| | findings (11 correct) |
|---|---|
| before, `GOMAXPROCS=16` | 6, 7, 8, 8, 8, 8, 9, 7, 9, 7, 9, 11 |
| before, `GOMAXPROCS=1` | 11 × 12 |
| after, `GOMAXPROCS=16` | 11 × 12 |

This is the "non-reproducible anomaly" recorded but left unexplained in Sprint
25, and the same cause behind the intermittent failures previously written off
as needing `go test -p 1`.

Fixed by iterating the three index buckets separately rather than merging
them, which also removes a per-call-node allocation.

**`go test -race` reports it every time; a plain `go test` does not.** Verified
by reintroducing the bug. CI's CGo leg now runs `-race`, and that flag is
load-bearing, not hygiene — dropping it silently retires
`TestMatch_ConcurrentSharedIndex`.

### Blast radius, stated precisely

The collision needs enough concurrent call-node matching to occur, so it
scaled with codebase size. Small targets were unaffected; the largest was not:

| Target | pre-fix (×3) | post-fix (×3) |
|---|---|---|
| WebGoat (1231 files) | **142, 132, 139** | **152, 152, 152** |
| DVWA | 93, 93, 93 | 93, 93, 93 |
| Damn-Vulnerable-dotNet | 17 × 3 | 17 × 3 |
| Vulnerable-Flask-App | 11 × 3 | 11 × 3 |
| dvna | 7 × 3 | 7 × 3 |

WebGoat was losing 10–20 findings per run, non-deterministically. An earlier
claim in this sprint's first commit message that the bug was "deflating every
measurement" was too broad and is corrected here: it deflated large scans.

## 3. Multi-value assignment was destroying taint

`BuildContext` keyed taint on an assignment's whole LHS text, so Go's
`num, _ := strconv.Atoi(val)` stored the key `"num, _"` and left bare `num`
untainted — across effectively every `value, err := fn()`, Go's universal call
idiom. `taint.lhsNames` now splits the LHS into the names it binds (skipping
Go's blank identifier). `Attrs["lhs"]` is deliberately left intact so rules
matching on `lhs_identifier` are unaffected. Python tuple unpacking gets the
same fix for free.

Two immediate consequences on `damn-vulnerable-golang`:

- `ZS-GO-018` (reflected XSS) now fires on
  `filePath := r.URL.Query().Get("path"); data, err := os.ReadFile(filePath); w.Write(data)`
  — the multi-value line was breaking the chain. Semgrep flags the same line.
- **`ZS-GO-046`** (new): int16 narrowing on a tainted value, CWE-190. This rule
  existed as `ZS-GO-014`, was found never to fire, and was removed in Sprint 28
  rather than shipped broken. The rule was never the problem. `ZS-GO-014` has
  since been reused for `tx.Query` SQLi, hence the new ID.

## 4. Differential coverage harness

`scripts/differential.py` runs ZeroStrike and Semgrep OSS over the same target
and buckets findings by `(file, CWE)` with a line tolerance: **both**,
**semgrep-only** (the gap list), **zerostrike-only**. Semgrep's output is
another tool's opinion, not ground truth — this ranks work, it does not grade
correctness.

It exists because the in-repo corpus cannot answer this question. Fixtures are
copied from `testdata/` and expectations are written by whoever wrote the rule,
so `FN=0` is structural and 100% recall means "no regressions", not
"competitive".

### Results — 6 of 7 targets

| Target | ZeroStrike | Semgrep | both | semgrep-only | zerostrike-only |
|---|---|---|---|---|---|
| DVWA (php) | 93 | 118 | 29 | 89 | 64 |
| Damn-Vulnerable-dotNet (cs) | 17 | 86 | 10 | 76 | 7 |
| Vulnerable-Flask-App (py) | 11 | 28 | 2 | 26 | 9 |
| damn-vulnerable-golang (go) | 11 | 13 | 5 | 8 | 6 |
| dvna (js) | 7 | 26 | 5 | 21 | 2 |
| dvpwa (py) | 0 | 8 | 0 | 8 | 0 |
| **total** | **139** | **279** | **51** | **228** | **88** |

**We reproduce 18.3% of Semgrep's findings.** WebGoat is excluded: its Semgrep
pass exceeded 40 minutes and was stopped, so its differential is still open.

### Ranked gap list — what to build next

```
  61  csharp/CWE-89     SQL injection
  21  php/CWE-94        code injection
  20  other/CWE-353     missing integrity check
  20  other/CWE-1357    reliance on uncontrolled component
  19  php/CWE-78        command injection
  10  php/CWE-697       incorrect comparison
  10  php/CWE-89        SQL injection
   6  javascript/CWE-95, csharp/CWE-614, javascript/CWE-522
   5  javascript/CWE-1333, python/CWE-89
```

**C# SQL injection alone is 61 of 228 misses — 27% of the entire gap.** Its
root cause is already known and independently confirmed this sprint: function
parameters are never seeded as taint sources.

`dvpwa` is the cleanest demonstration. It scores 0 findings on 40 files of a
deliberately vulnerable SQLi app, because every DAO takes its input as a
parameter:

```python
q = ("INSERT INTO students (name) VALUES ('%(name)s')" % {'name': name})
await cur.execute(q)          # `name` is a bare parameter -> never tainted
```

## 5. Ground truth: damn-vulnerable-golang

The only target that annotates its own vulnerabilities inline (12 CWE
comments), so the only one where "does it find what the repo documents" is
answerable without a second tool's opinion.

**8 of 12 detected.** Classified honestly:

| Documented | Status |
|---|---|
| CWE-798 hardcoded creds, CWE-327 ×3 weak crypto, CWE-22 traversal, CWE-338 weak PRNG | detected |
| CWE-326 inadequate encryption strength | detected, reported as CWE-327 (label mismatch, not a miss) |
| CWE-88 argument injection | detected as CWE-918 SSRF — the repo's own comment text says SSRF, so our label is the better one |
| **CWE-190 integer overflow** | **now detected** via the new `ZS-GO-046` (was a miss) |
| CWE-78 command injection | not flagged — the "user input" is a hardcoded literal; correct for a taint-gated engine, but gosec/semgrep flag the pattern regardless |
| CWE-89 SQL injection | same: `fmt.Sprintf` over two string literals, no taint |
| CWE-409 decompression bomb | genuine gap, no rule for `gzip.NewReader` without a limit |

The two literal-only cases are a deliberate design difference, not defects: a
taint-gated rule will not fire on hardcoded data. Whether to add
pattern-only siblings that flag the shape regardless of taint is a real
question this raises — gosec does, and it is why semgrep reports them.

## Verification

- `go test ./... -race` (CGo) green; `CGO_ENABLED=0 go test ./...` green; `go vet` clean.
- Benchmark corpus: **TP=451 FP=0 FN=0**, stable across repeated runs (was
  TP=433 FN=2 on the first honest CGo run, and both of those "false negatives"
  were the race, not rule defects).
- `CGO_ENABLED=0` bench exits 2 instead of scoring.

## Known limitations

- WebGoat's differential is incomplete (Semgrep timeout).
- The harness matches on `(file, CWE)` with a ±3 line tolerance; findings
  where either tool omits CWE metadata fall back to exact-line matching, which
  under-counts agreement.
- `zerostrike-only` (88) is not claimed as an advantage. It mixes genuine edge
  (secrets/SCA/framework checks Semgrep's `--config=auto` does not run the same
  way) with probable false positives. It has not been triaged.
- Single-file scan targets produce no output; only directories work. Not
  investigated this sprint.
