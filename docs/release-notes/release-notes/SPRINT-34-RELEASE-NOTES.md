# Sprint 34 — Argument-position matching, and paying back the precision debt

**v0.28.0**

v0.27.0 traded precision for recall: seeding function parameters as taint
sources found 18 real SQL injections, and also made the format-string rules
fire ~11 more times on code that was never vulnerable. That was disclosed at
the time as the known cost. This sprint pays it back.

---

## The defect

Every argument filter in the engine was "any argument, anywhere in its
subtree". There was no way to say *which* argument matters. That is wrong for
any sink where exactly one position is dangerous, and the format-string family
is the clearest case:

```csharp
string.Format("User: {0}", username)   // safe — literal format, value substituted
string.Format("User: " + username)     // vulnerable — attacker controls the format
```

Both fired. The first is the ordinary logging idiom, so the rule was noise by
construction. This was documented as a known imprecision well before v0.27.0
(`ZS-CS-013`, `ZS-JAVA-012` carry the same caveat); parameter seeding did not
create it, it just made it visible.

## The fix

New filter field `tainted_argument_index`, narrowing `tainted_argument` to a
single 0-based positional argument. Applied to all six format-string rules —
`ZS-CS-019`, `ZS-GO-023`, `ZS-JAVA-024`, `ZS-JS-034`, `ZS-PHP-017`,
`ZS-TS-032` — as index 0, meaning "only the format string itself".

### Positional indexing is not obvious, and getting it wrong is silent

Three distinct IR shapes had to be handled, each found by probing real parser
output rather than assuming:

| Builder | Shape |
|---|---|
| Go, C#, JS/TS, PHP | callee, then **one unnamed `argument_list` wrapper** delimited by `(` `)` |
| Java | callee, then arguments as **direct children** beside literal `(` and `)` tokens |
| C#, PHP | a string-concatenation argument lowers to an **`unknown` node with empty text** |

Naive `Children[1+i]` indexing treats Java's open paren as argument 0. Skipping
empty-text nodes as punctuation deletes C#'s and PHP's real arguments. The
wrapper is identified by its delimiters (`(` … `)`), never by empty text, for
exactly that reason. Two intermediate versions of this change were wrong in
opposite directions and were caught by the corpus, not by reasoning.

## Before / after

Format-string findings on real targets, and what they cost:

| Target | v0.27.0 total | **v0.28.0 total** | format-string findings |
|---|---|---|---|
| Damm-Vulnerable-dotNet | 53 | **44** | 9 → **0** |
| DVWA | 111 | **109** | 2 → **0** |
| dvna | 10 | 10 | 0 → 0 |
| Vulnerable-Flask-App | 11 | 11 | 0 → 0 |
| damn-vulnerable-golang | 11 | 11 | 0 → 0 |
| dvpwa | 3 | 3 | 0 → 0 |

**11 false positives removed, zero real findings lost.** Verified directly: a
scan of the safe idiom in C#, PHP, Go and Java produces no findings at all,
while the genuinely-vulnerable form still fires in all six languages.

Corpus: **TP=451 FP=0 FN=0**, unchanged.

Cumulative across the three sprints:

| | v0.25.4 | v0.26.0 | v0.27.0 | **v0.28.0** |
|---|---|---|---|---|
| real-target findings | 269–279 | 291 | 351 | **340** |
| deterministic | no | yes | yes | yes |
| corpus | 53 expectations | 450 | 451 | 451 |

The drop from 351 to 340 is the point of this release, not a regression.

## The corpus was asserting false positives as true positives

Four format-string fixtures used the **safe** idiom and expected a finding:

```java
return String.format("User: %s", username);   // vuln_format_string.java
```

```php
$greeting = sprintf("User: %s", $username);   // vuln_format_string.php
```

C# and Go were the same; only JS and TS described a real vulnerability. So the
corpus had locked in the imprecision — a rule that stopped producing this
false positive would have *failed* the accuracy gate.

This is the self-authored-corpus weakness described in Sprint 32 showing up in
practice: fixtures written by the rule's author encode the rule's behaviour,
not the security truth. All four now describe genuinely attacker-controlled
format strings, and `clean.cs` carries the safe idiom as an explicit negative
so the false positive cannot come back.

## Verification

- `go test ./... -race` (CGo) green; `CGO_ENABLED=0 go test ./...` green; `go vet` clean.
- `TestMatch_TaintedArgumentIndex` covers both the wrapped and flat IR shapes,
  asserting tainted-argument-0 fires and tainted-argument-1 does not.
- Corpus TP=451 FP=0 FN=0.

## Known limitations

- Only the format-string family uses `tainted_argument_index`. Other rules with
  a single dangerous position have not been audited — that sweep is worth doing.
- The 134 zerostrike-only sites from the differential remain untriaged. This
  release removed 11 findings that were confidently wrong; it says nothing
  about the rest. Establishing a real-world false-positive rate is still the
  most valuable open work, ahead of closing the remaining 53-site recall gap.
- WebGoat's differential is still missing (Semgrep pass exceeds 40 minutes).
