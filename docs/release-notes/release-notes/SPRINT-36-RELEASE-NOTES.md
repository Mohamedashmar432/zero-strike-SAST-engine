# Sprint 36 — Constructor-aware argument resolution

**v0.30.0**

Completes the SQL argument-position audit left open in v0.29.0, by fixing the
engine limitation that forced three rules to be excluded from it.

---

## The limitation

`argumentNodes` assumed a call node was `[callee, argument_list]`. That is true
for method calls in Go, C#, JS/TS and PHP, and Java's flat
`[callee, "(", arg, ")"]` shape was already handled. A C# **constructor** is
neither:

```
new SqliteDataAdapter(sql, connection)

  [0] unknown     "new"
  [1] identifier  "SqliteDataAdapter"     <- the type name
  [2] unknown     ""  (the argument list)
```

Assuming the argument list follows the callee made the **type name** argument 0.
In v0.29.0 that caused pinning `ZS-CS-002`/`ZS-CS-007`/`ZS-CS-011` to argument 0
to match a type identifier — never tainted — silently dropping 21 real SQL
injections on Damm-Vulnerable-dotNet while the corpus still reported
`TP=451 FP=0 FN=0`. Those three rules were left unpinned as a result.

## The fix

`argumentNodes` now locates the argument list by its `(` … `)` delimiters
wherever it appears among the children, rather than assuming a position. All
three shapes are handled from one code path:

| Shape | Children |
|---|---|
| method call (Go, C#, JS/TS, PHP) | `[callee, argument_list]` |
| constructor (C#) | `["new", TypeName, argument_list]` |
| Java | `[callee, "(", arg, ",", arg, ")"]` |

`ZS-CS-002`, `ZS-CS-007` and `ZS-CS-011` are now pinned to argument 0, closing
the last gap in the SQL audit.

## Before / after

Damm-Vulnerable-dotNet, `ZS-CS-011`: **18 → 17**, and the one removed is a
confirmed false positive:

```csharp
SqliteDataAdapter da = new SqliteDataAdapter("select * from Products", connection);
```

The SQL is a hardcoded literal; it only ever fired because the *connection*
argument was tainted. The 17 that remain are the genuine injections where a
method parameter is concatenated into the query.

| Target | v0.29.0 | **v0.30.0** |
|---|---|---|
| Damm-Vulnerable-dotNet | 44 | **43** |
| DVWA | 109 | 109 |
| dvpwa | 0 | 0 |
| Vulnerable-Flask-App | 11 | 11 |
| damn-vulnerable-golang | 11 | 11 |
| dvna | 10 | 10 |

Corpus: **TP=451 FP=0 FN=0**, unchanged.

Cumulative precision work across three sprints: **15 false positives removed,
zero real findings lost.**

## Verification

`TestArgumentIndex_ConstructorShape` asserts both directions on the constructor
layout — tainted SQL in argument 0 fires, a literal query with a tainted
connection does not — so the type-name-as-argument-0 bug cannot return
silently. `TestMatch_TaintedArgumentIndex` continues to cover the wrapped and
flat shapes.

`go test ./... -race` green, `CGO_ENABLED=0 go test ./...` green, `go vet`
clean, corpus TP=451 FP=0 FN=0, and all six real targets re-scanned.

## Known limitations

- `mysqli_query($link, $query)` and `pg_query($conn, $query)` put the query at
  index **1**, and `pg_query` has a one-argument overload — they need
  overload-aware handling before they can be pinned. Still unpinned.
- `collection.find` (Mongo) takes a filter document rather than SQL; out of
  scope for this audit.
- dvpwa's genuine injection in `student.py` remains missed — most likely the
  documented file-scoped, flow-insensitive taint model.
- WebGoat's differential is still missing; Java remains unmeasured against
  Semgrep.
