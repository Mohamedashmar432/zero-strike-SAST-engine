# Sprint 38 — WebGoat measured at last; receiver-agnostic printStackTrace

**v0.32.0**

WebGoat was the one target never compared against Semgrep — its unscoped
Semgrep pass exceeded 40 minutes. Scoping to `--config=p/java --include='*.java'`
brings it to a tractable run over 405 Java files, closing the last measurement
blind spot.

## Result

| WebGoat, Java only | before | **after** |
|---|---|---|
| sites we find | 93 | **95** |
| Semgrep finds | 39 | 39 |
| agreed | 11 | **19** |
| Semgrep-only | 28 | **20** |
| overlap | 28.2% | **48.7%** |

**We report 95 Java sites to Semgrep's 39** — roughly 2.4x — so the Java surface
was never weak; it was simply unmeasured.

## Two causes behind the apparent 28-site gap

**Receiver pinning, again.** `ZS-JAVA-038` matched `e.printStackTrace` and
`ZS-JAVA-039` matched `ex.printStackTrace` — two rules, two hardcoded variable
names. WebGoat also uses `sqle.printStackTrace()` and
`exception.printStackTrace()`. Consolidated into one receiver-agnostic rule
using the single-segment `callee_suffix` added in v0.27.0, constrained with
`argument_count: 0` to select the no-arg overload. `ZS-JAVA-039` is removed as
subsumed and its corpus case repointed. We now find all 8 sites.

**A CWE taxonomy mismatch in the harness.** Even after finding all 8, the
differential still counted them as misses: we tag printStackTrace CWE-209
(error message containing sensitive information), Semgrep tags it CWE-489
(active debug code) — on byte-identical sites, verified file-and-line. Added
489 to the information-exposure equivalence class. That single alias accounts
for 8 of the 28.

This is the fourth harness defect found by inspecting results rather than
trusting them. Every one inflated the gap.

## Remaining Java gap: 20 sites

```
  13  SQL injection   (formatted-sql-string 8, tainted-sql-string 3,
                       java-sql-sqli 1, deepsemgrep 1)
   7  tainted-html-string-responsebody   (Spring @ResponseBody XSS)
```

Two coherent classes rather than a scatter — worth addressing as two pieces of
work, not twenty.

## Verification

`go test ./... -race` green, `CGO_ENABLED=0 go test ./...` green, `go vet`
clean, corpus **TP=451 FP=0 FN=0**. WebGoat 181 → 183 findings.
