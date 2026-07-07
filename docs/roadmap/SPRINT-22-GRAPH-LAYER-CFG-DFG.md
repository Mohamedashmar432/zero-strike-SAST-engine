# Sprint 22 — Graph Layer (CFG/DFG)

Referenced from `internal/analyzer/taint/taint.go` and `internal/graph/graph.go`.
This is a scope note for the graph layer, not a full sprint report — see
`docs/release-notes/release-notes/SPRINT-21-22-RELEASE-NOTES.md` for that.

## What shipped

`internal/graph` builds two structures over Python IR, gated behind
`--enable-graphs` (default off, zero cost when disabled):

- **CFG** (`NewCFG`): control-flow edges for if/elif/else, for/while (with a
  loop-back edge), try (main body only), return (to an implicit exit), and
  sequential fall-through between statements in the same Module/Block.
- **DFG** (`NewDFG`): definition/use collection plus a standard fixed-point
  reaching-definitions analysis over the CFG.

`internal/analyzer/taint` consumes the DFG to populate
`TaintContext.Path` — the source-to-sink location chain — for taint
verdicts derived from propagation through a referenced tainted variable.
Verdicts derived directly from a source-pattern match, or from a same-file
function-call summary, aren't chained (see `taint.extendPath`'s doc
comment); the flow-insensitive taint verdict itself is unaffected either
way — only whether a precise path can be attached.

## Fixed: statement-wrapper unwrapping

The real tree-sitter Python grammar wraps every top-level statement line in
its own `simple_statements` node, which has no dedicated `ir.NodeKind` and so
maps to `NodeKindUnknown` — meaning a straight-line sequence of statements
under `Module`/`Block` has each statement as a *grandchild*, not a direct
child. `NewCFG`'s sequential fall-through pass originally only looked at
direct children, so it silently never connected consecutive top-level
statements at all — confirmed by a CGO-enabled test run
(`TestIntegration_EnableGraphsPopulatesTaintPath` failing) once a real `gcc`
became available to actually build this package; the hand-built-IR fixtures
in `internal/graph/graph_test.go` had statements as direct children and never
exercised this shape. Fixed via `flattenStatements`, which unwraps
`NodeKindUnknown` containers the same way `directOrWrappedBlocks` already did
for elif/else clauses. See the Sprint 21+22 release notes' "Bug found and
fixed" section for the full diagnosis.

## Known ceiling: branch-exit-point threading

The CFG connects a branch/loop *header* node to the next sibling statement,
not each branch's last inner statement to that sibling. Concretely:

```python
if cond:
    x = tainted_source()
y = x  # DFG may not confirm x's definition reaches here
```

A definition made only inside one arm of an `if` isn't threaded through to
code after the `if` as a confirmed reaching definition. When the DFG can't
confirm a reaching definition for a referenced variable, `taint.BuildContext`
still trusts the (flow-insensitive) taint verdict — it just omits `Path`
rather than asserting an unconfirmed chain.

Fixing this needs each block to track its own exit point(s) and merge them at
the join after the branch/loop — normal control-flow-graph construction, just
not implemented this sprint. Straight-line and single-branch-body taint
chains (the common case, and what this sprint's fixtures cover) are
unaffected.

## CallGraph: deferred

`graph.CallGraph` is an empty type. Real cross-file taint tracking needs
caller/callee edges, which in turn needs a two-phase scan: a first pass that
builds a global symbol/function-summary table across every file, then a
second pass that matches with full cross-file visibility. Today's
`SASTScanner.Scan()` is a single-pass-per-file worker pool — restructuring it
is a separate, larger architectural change than the graph layer itself, so
it's out of scope here.

## Language scope

CFG/DFG are Python-only this sprint. Other languages get nil CFG/DFG
regardless of `--enable-graphs` — extending this to another language means
implementing that language's own `NewCFG`/`NewDFG` equivalent (or, if the
node-kind shapes line up, reusing `internal/graph` directly), gated the same
way `internal/analyzer.New` gates Python today.
