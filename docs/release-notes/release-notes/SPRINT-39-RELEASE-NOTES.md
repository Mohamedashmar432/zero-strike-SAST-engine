# Sprint 39 — Java SQL sinks matched on any receiver

**v0.33.0**

The WebGoat differential in v0.32.0 left a 20-site Java gap, 13 of it SQL
injection. Inspecting those sites showed the same cause found three times
before: the rule was pinned to one hardcoded receiver variable name.

```java
stmt.executeQuery(query)       // ZS-JAVA-001 matched this
statement.executeQuery(query)  // ...and missed this, which is what WebGoat writes
```

`ZS-JAVA-001` (executeQuery), `ZS-JAVA-010` (executeUpdate) and `ZS-JAVA-037`
(execute) now use a single-segment `callee_suffix`, matching the method on any
receiver. Precision is unaffected: each already carries
`tainted_argument_index: 0`, so only a tainted query string fires.

## Before / after

| WebGoat, Java only | v0.32.0 | **v0.33.0** |
|---|---|---|
| sites we find | 95 | **110** |
| agreed with Semgrep | 19 | **25** |
| Semgrep-only | 20 | **14** |
| overlap | 48.7% | **64.1%** |

WebGoat total 183 → 198. DVWA (109), Damm-Vulnerable-dotNet (43) and dvna (10)
are byte-identical — no collateral. Corpus **TP=451 FP=0 FN=0**.

## Remaining Java gap: 14 sites

```
   7  tainted-html-string-responsebody   Spring @ResponseBody XSS
   6  SQL injection (query-construction lines and no-arg PreparedStatement forms)
   1  spring-unvalidated-redirect
```

The residual SQL entries are a different shape from the ones just fixed:
Semgrep flags the line where the query string is *built*, or a no-argument
`statement.executeQuery()` whose SQL was set earlier via `prepareStatement`.
Neither is reachable by a sink rule on the execute call; the second needs
taint to follow a value across the PreparedStatement object.

## Note on receiver pinning

This is the fourth time it has cost real detections — `cursor.execute`,
`tx.Query`, `e.printStackTrace`, and now `stmt.executeQuery`. A sweep of the
remaining dotted-callee rules for receiver names that only match one
conventional spelling is worth doing deliberately rather than one differential
at a time.
