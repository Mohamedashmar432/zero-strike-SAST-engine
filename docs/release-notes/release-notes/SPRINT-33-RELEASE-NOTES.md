# Sprint 33 — Closing the real-world recall gap

**v0.27.0**

Two engine changes driven by the Sprint 32 differential, plus a correction to
the differential itself — which turned out to be overstating the gap by a
factor of four.

---

## 1. The measured gap was mostly a measurement bug

Sprint 32 reported 228 semgrep-only findings and a 18.3% overlap. Triage found
three flaws in the harness, all inflating the number:

**Semgrep rule granularity.** A single `exec("ping " . $target)` in DVWA is
reported by Semgrep under four separate rule ids (`tainted-exec`, `exec-use`,
`tainted-command-injection`, `laravel-command-injection`). `pair_up` spends one
of our findings per one of theirs, so detecting that line correctly still
scored as three misses. We already flag those lines (`ZS-PHP-006` at
`exec/source/high.php:26,30`). Fixed with `collapse()`: one source line is one
vulnerability site, on both sides.

**CWE taxonomy splits.** We label md5 as CWE-327 (broken algorithm), Semgrep as
CWE-328 (weak hash). Same line, same defect, scored as a miss. Fixed with
`CWE_ALIASES` equivalence classes.

**Missing-CWE handling.** Many Semgrep rules carry no CWE at all. The old code
demanded an *exact* line match in that case, so `string-to-int-signedness-cast`
at `main.go:137` scored as a miss against our own `ZS-GO-046` at `main.go:138`.
Now the normal line tolerance applies either way.

**Semgrep false positives.** 61 C# "SQLi" findings pass their values as
`$param`/`@param` placeholders and concatenate only a constant table name — 60
of 61, with zero concatenating a variable. 9 `md5-loose-equality` findings fire
on `mysqli_num_rows($result) == 1`, which is not a hash comparison.

| | reported | actual |
|---|---|---|
| semgrep-only | 228 | **56** |
| in-scope overlap | 18.3% | **48.6%** |

The lesson is in the harness's own docstring, which I wrote and then ignored:
Semgrep's output is another tool's opinion, not ground truth. It must be
triaged before it is ranked.

## 2. Sink rules were pinned to one hardcoded receiver name

`ZS-PY-004`, the flagship Python SQL-injection rule, matched `cursor.execute`
with `callee_suffix`. That fires only when the variable is literally named
`cursor`:

```python
cursor.execute(...)   # matched
cur.execute(...)      # missed
conn.execute(...)     # missed
session.execute(...)  # missed
```

dvpwa — a deliberately vulnerable SQL-injection app — scored **0 findings
across 40 files** largely for this reason: its DAOs use `cur`. The same shape
pins `ZS-GO-014` to variables named `tx` and `ZS-GO-002` to `db`.

A single-segment `callee_suffix` now means "this method on any receiver".
`calleeSuffixMatches` already handled it correctly (`.execute` is a
dot-boundary suffix of `cur.execute`); only `BuildIndex` and the Validator
were rejecting it. Precision comes from the rule's own filters — every rule
using this is taint-gated.

## 3. Function parameters are now taint sources

Taint previously only existed where it both originated and was consumed inside
one function body. Real code splits those: the handler extracts, a helper does
the dangerous thing.

This is the change that mattered most, and the evidence is unambiguous —
`WebGoat/App_Code/DB/SqliteDbProvider.cs`:

```csharp
public bool IsValidCustomerLogin(string email, string password)
    string sql = "select * from CustomerLogin where email = '" + email + "' ...
    SqliteDataAdapter da = new SqliteDataAdapter(sql, connection);
```

**18 real SQL injections in that one file, previously invisible.** Semgrep
misses all of them — its C# SQLi findings were entirely in the *parameterized*
membership-provider files, i.e. its false positives.

## Before / after

Real vulnerable applications, findings per scan (all deterministic):

| Target | v0.25.4 (pre-Sprint-32) | v0.26.0 | **v0.27.0** |
|---|---|---|---|
| DVWA (php) | 93 | 93 | **111** |
| Damm-Vulnerable-dotNet (cs) | 17 | 17 | **53** |
| dvna (js) | 7 | 7 | **10** |
| dvpwa (py) | 0 | 0 | **3** |
| damn-vulnerable-golang (go) | 9 | 11 | 11 |
| Vulnerable-Flask-App (py) | 11 | 11 | 11 |
| WebGoat (java) | 132–142 (varying) | 152 | 152 |
| **total** | **269–279** | **291** | **351** |

Differential against Semgrep, site-level, corrected harness:

| | v0.26.0 | **v0.27.0** |
|---|---|---|
| sites we find | 134 | **193** |
| agreed with semgrep | 53 | **59** |
| addressable gap | 56 | **53** |
| in-scope overlap | 48.6% | **52.7%** |

Benchmark corpus: **TP=451 FP=0 FN=0**, unchanged and still deterministic —
neither change cost a single corpus false positive.

## Honest accounting of the new findings

Of 59 new findings, 6 are corroborated by Semgrep and the rest are
uncorroborated. Triaged:

- **18 `ZS-CS-011`** — real SQL injection in `SqliteDbProvider.cs`, parameters
  concatenated into SQL. High-value true positives.
- **6 `ZS-JS-002`** — `cell.innerHTML = user` in DVWA's `authbypass.js`, where
  `user` is a callback parameter carrying server response data. Real DOM XSS.
- **9 `ZS-CS-019`** — `string.Format` with a tainted argument. **This is noise.**
  The format-string rules were already documented as imprecise: the engine has
  no first-argument-only concept, so they fire on the safe
  `logger.info("User: %s", name)` idiom. Parameter seeding amplifies a
  pre-existing weakness rather than creating a new one.
- Remainder not individually triaged.

Uncorroborated is not the same as wrong — Semgrep missed the 18 real SQLi
entirely — but it is also not verified, and it is not claimed as such.

## Known limitations

- **Format-string rules need first-argument targeting.** `ZS-CS-019` and its
  siblings (`ZS-JAVA-012`, `ZS-CS-013`) now fire more often. The fix is an
  argument-position filter in the engine, which does not exist today; until
  then these should probably drop to low confidence.
- Parameter seeding is unconditional — every parameter of every function, not
  just entry-point-shaped ones. Type-aware or handler-only seeding would be
  more precise. This is the version whose cost is measurable; narrow it if the
  false-positive rate says to.
- The 134 zerostrike-only sites remain largely untriaged. We still do not know
  our real-world false-positive rate, and the corpus (FP=0) cannot tell us —
  it only proves we do not fire on fixtures written not to fire.
- WebGoat's differential is still missing (Semgrep pass exceeds 40 minutes).
- Remaining 53-site gap: php 21, javascript 14, python 8, csharp 4, go 4.
