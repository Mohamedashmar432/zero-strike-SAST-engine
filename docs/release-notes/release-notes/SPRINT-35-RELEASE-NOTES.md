# Sprint 35 — SQL argument-position audit, and the first real false-positive triage

**v0.29.0**

Sprint 34 added `tainted_argument_index` and used it on the format-string
family. This sprint triaged our own uncorroborated findings for the first time,
found the same defect in the SQL sink family, and fixed it — carefully, because
the first attempt silently destroyed 21 real detections.

---

## Triage: what our uncorroborated findings actually are

The differential leaves 123 sites that we report and Semgrep does not. Until
now we had no idea whether those were our edge or our noise — the corpus
(FP=0) cannot answer it, since it only proves we do not fire on fixtures
written not to fire.

Every group above two occurrences was checked against real code:

| Rule | n | Code | Verdict |
|---|---|---|---|
| ZS-PHP-010 | 20 | `$pass = md5($pass)` | real — MD5 password hashing |
| ZS-PHP-002 | 18 | `mysqli_query(..., $query)` built from `$_GET` | real |
| ZS-CS-011 | 18 | method parameters concatenated into SQL | real |
| ZS-PHP-015 | 7 | `header("location: " . $_GET['redirect'])` | real — open redirect |
| ZS-JS-002 | 6 | `cell.innerHTML = user` | real DOM XSS |
| ZS-PHP-012 | 5 | `setcookie` without secure/httponly | real |
| ZS-PY-020 | 4 | `user.password = 'admin123'` | real |
| **ZS-PY-004** | **3** | **`cur.execute('… WHERE id = %s', (id_,))`** | **false positive** |

The headline is reassuring: the large majority of what Semgrep misses and we
report is genuinely vulnerable code. "Uncorroborated" was mostly our edge.

## The one false positive was the worst kind

`ZS-PY-004` was flagging **correctly parameterised queries**:

```python
await cur.execute('SELECT id FROM users WHERE id = %s', (id_,))
```

DB-API takes values as a separate sequence precisely so they never become part
of the SQL. This is the recommended form, and flagging it trains people away
from parameterisation — the single most damaging false positive a SAST tool can
produce. It fired because `tainted_argument` matched any argument and `id_` is
a seeded parameter in position 1: the same defect fixed for format strings in
Sprint 34, sitting unnoticed in the SQL family.

## The fix, and the part that went wrong first

Sixteen SQL rules now pin the query to argument 0 — Go (`db.Query`, `db.Exec`,
`tx.Query`, `tx.Exec`, `db.QueryRow`, `tx.QueryRow`), JS/TS (`pool.query`,
`client.query`, `connection.query`, `knex.raw`, `db.sequelize.query`), Java
(`stmt.execute*`), and Python (`execute`, `cursor.executescript`).

Verified rather than assumed:

```go
db.Query("SELECT * FROM users WHERE id = ?", id)   // silent   (parameterised)
db.Query("SELECT * FROM users WHERE id = " + id)   // fires    (concatenated)
```

```js
pool.query('SELECT * FROM users WHERE id = $1', [id]);  // silent
pool.query('SELECT * FROM users WHERE id = ' + id);     // fires
```

**Three rules were deliberately reverted.** The first pass also pinned
`ZS-CS-002`, `ZS-CS-007` and `ZS-CS-011`, which dropped the Damm-Vulnerable-dotNet
target from 44 findings to 23 — **21 real SQL injections silently lost**, while
the corpus still reported TP=451 FP=0 FN=0. Those rules match C# *constructor*
calls (`new SqliteDataAdapter(sql, connection)`), where the type name occupies a
child slot so positional argument 0 does not resolve to the SQL string.
`argumentNodes` needs to understand constructors before those can be narrowed;
until then they stay unpinned, with the reason recorded in each rule file.

Also excluded on purpose: `mysqli_query($link, $query)` and `pg_query($conn,
$query)` put the query at index **1**, and `pg_query` has a one-argument
overload; `collection.find` takes a filter document, not SQL.

## Before / after

| Target | v0.28.0 | **v0.29.0** | change |
|---|---|---|---|
| DVWA | 109 | 109 | — |
| Damm-Vulnerable-dotNet | 44 | 44 | — (21 real findings preserved) |
| dvpwa | 3 | **0** | 3 parameterised-query false positives removed |
| Vulnerable-Flask-App | 11 | 11 | — |
| damn-vulnerable-golang | 11 | 11 | — |
| dvna | 10 | 10 | — |

Corpus: **TP=451 FP=0 FN=0**, unchanged throughout.

Cumulative precision work across two sprints: **14 false positives removed**
(11 format-string, 3 parameterised-query) with **zero real findings lost**.

## What this says about the corpus

For the second sprint running, the corpus passed while something real broke.
In Sprint 34 it was asserting a false positive as required behaviour; here it
stayed green through the loss of 21 true positives on a real application. A
self-authored corpus verifies that rules still do what their author intended —
it cannot verify that the intent was right, and it contains no code the rules
were not written against. **The real-target scans are the safety net; the
corpus is only a regression gate.**

## Known limitations

- C# constructor-style SQL sinks remain unpinned (`ZS-CS-002/007/011`).
- `mysqli_query`/`pg_query` need index 1 plus overload handling.
- Remaining uncorroborated findings below 3 occurrences were not triaged
  individually: `ZS-JS-023` fires on `Math.random` inside minified vendored
  jQuery, which is technically correct but not actionable — vendor/minified
  path exclusion is a scanning-scope question, not a rule bug.
- dvpwa's genuine injection in `student.py` is still missed. Both the
  interpolated and parameterised shapes behave correctly in isolation, so the
  cause is most likely the documented file-scoped, flow-insensitive taint model
  (several functions in that file reuse the variable `q`).
- WebGoat's differential is still missing; the whole Java picture is unmeasured
  against Semgrep.
