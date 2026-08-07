# Sprint 37 — Negative argument indexing; SQL audit complete

**v0.31.0**

The last two SQL sinks left unpinned by v0.29.0/v0.30.0 were overloaded, and no
fixed non-negative index described them.

## The problem

```php
pg_query($query);                  // query is argument 0
pg_query($conn, $query);           // query is argument 1
mysqli_query($link, $query);       // query is argument 1
```

The query is the **last** argument in every form. `tainted_argument_index: 0`
would miss the two-argument calls; `1` would miss `pg_query`'s single-argument
overload and would also match a tainted connection handle as if it were SQL.

## The fix

`argumentAt` now accepts a negative index, counting from the end: `-1` is the
last argument. `ZS-PHP-002` (mysqli_query) and `ZS-PHP-009` (pg_query) use it.

Verified against all four shapes:

```php
mysqli_query($link, "SELECT ... " . $id);   // fires
mysqli_query($link, "SELECT * FROM t");     // silent
pg_query("SELECT ... " . $id);              // fires  (1-arg overload)
pg_query($link, "SELECT * FROM t");         // silent
```

## Before / after

DVWA is **byte-identical at 109 findings with zero rules changed** — this is a
purely defensive change. It removes the possibility of a tainted connection
handle being read as SQL injection without touching any real detection. Every
other target unchanged; corpus **TP=451 FP=0 FN=0**.

The SQL argument-position audit is now complete: 21 rules pinned across Go,
JS/TS, Java, Python, C# and PHP. `collection.find` (Mongo) is deliberately
excluded — it takes a filter document, not SQL.

## Cumulative precision work, sprints 34-37

| | |
|---|---|
| False positives removed | **15** |
| Real findings lost | **0** |
| Corpus | TP=451 FP=0 FN=0 throughout |
| New engine capability | `tainted_argument_index`, incl. negative indexing and three call-node layouts |

## Known limitations

- dvpwa's genuine injection in `student.py` remains missed — most likely the
  documented file-scoped, flow-insensitive taint model.
- WebGoat's differential is still missing; Java is unmeasured against Semgrep.
- Remaining recall gap: 53 sites (php 21, js 14, python 8, csharp 4, go 4).
