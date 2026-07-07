// Package taint performs a lightweight, file-scoped taint pass over Python,
// JavaScript, TypeScript, and C# IR. It exists to reduce false positives on
// injection rules that previously fired on any call to a sink function,
// regardless of whether the argument actually came from untrusted input.
//
// The pass is text-based and flow-insensitive within a file: it walks
// assignments in source order and keeps one final tainted-variable set per
// file. It understands per-language source and sanitizer patterns (see
// patterns.go) and same-file function calls via per-function summaries
// (see summary.go).
package taint

import (
	"github.com/zerostrike/scanner/internal/core"
	"github.com/zerostrike/scanner/internal/graph"
	"github.com/zerostrike/scanner/internal/ir"
	"github.com/zerostrike/scanner/internal/symboltable"
)

// Result is the output of BuildContext: which variables are tainted, and a
// human-readable reason for each — the RHS text/expression that most
// recently caused the taint verdict.
type Result struct {
	Tainted map[string]bool
	Reasons map[string]string // keyed by variable name, only set when Tainted[name] is true
	// Paths holds the source-to-sink location chain for each tainted
	// variable, only populated when BuildContext is given a non-nil *graph.DFG
	// (i.e. --enable-graphs). A variable can be Tainted with no entry in
	// Paths if the DFG couldn't confirm its definition reaches this point
	// (see extendPath) — the flow-insensitive verdict is still trusted, the
	// precise path just isn't.
	Paths map[string][]core.Location
}

// Build walks file in source order and returns the set of variable names
// whose value may originate from an untrusted source. It is a thin wrapper
// over BuildContext for callers that don't need the taint reasons.
//
// Every assignment overwrites its LHS entry with a fresh verdict:
//
//   - RHS matches a sanitizer call     → false (clears prior taint)
//   - RHS matches a source pattern     → true
//   - RHS references a tainted name    → true
//   - RHS calls a same-file function whose summary is alwaysTainted, or is
//     a pass-through called with a tainted argument → true
//   - none of the above                → false (this overwrite is the fix
//     for the historical never-clears bug: x = "literal" now un-taints x)
//
// Augmented assignments (x += y) additionally keep the LHS's previous
// verdict, since the prior value flows into the result.
//
// ponytail: taint is tracked per file, not per function scope, and the map
// is flow-insensitive (one final verdict per name for the whole file).
// Consequences: (1) two functions reusing a variable name can still
// interact — the *last* assignment in source order wins, so a later clean
// reassignment in one function clears taint that another function's sink
// already saw (possible false negative), and a later tainted assignment
// still cross-contaminates an earlier clean use (possible false positive);
// (2) same-file pass-through/always-tainted function calls ARE now tracked
// via summaries, and reassignment-to-clean now clears taint. Cross-file
// taint and true flow-sensitivity need the CFG/DFG graph layer (deferred —
// see docs/roadmap/SPRINT-22-GRAPH-LAYER-CFG-DFG.md).
func Build(file *ir.IRFile, symbols symboltable.SymbolTable) map[string]bool {
	return BuildContext(file, symbols, nil).Tainted
}

// BuildContext performs the same walk as Build but additionally tracks, per
// tainted variable, the reason it's tainted — the RHS text of a matched
// source pattern, "propagated from <name>" for a tainted-identifier
// reference, or "tainted via <callee>(...)" for a same-file summarized call.
// See Build's doc comment for the full verdict rules.
func BuildContext(file *ir.IRFile, symbols symboltable.SymbolTable, dfg *graph.DFG) Result {
	tainted := make(map[string]bool)
	reasons := make(map[string]string)
	paths := make(map[string][]core.Location)
	if file == nil || file.Root == nil {
		return Result{Tainted: tainted, Reasons: reasons, Paths: paths}
	}
	pats := patternsFor(file.Language)
	summaries := buildSummaries(file, pats)
	ir.Walk(file.Root, func(n *ir.IRNode) bool {
		if n.Kind != ir.NodeKindAssignment {
			return true
		}
		lhs, _ := n.Attrs["lhs"].(string)
		if lhs == "" {
			return true
		}
		verdict, reason, ref := assignmentTaintsLHS(n, pats, summaries, symbols, tainted)
		if aug, _ := n.Attrs["augmented"].(bool); aug {
			if !verdict && tainted[lhs] {
				// Inherits the previous verdict; keep the previously
				// recorded reason instead of overwriting with empty.
				verdict = true
				reason = reasons[lhs]
				ref = lhs
			}
		}
		tainted[lhs] = verdict
		if verdict {
			reasons[lhs] = reason
			if dfg != nil {
				if p := extendPath(n, ref, dfg, paths); p != nil {
					paths[lhs] = p
				} else {
					delete(paths, lhs)
				}
			}
		} else {
			delete(reasons, lhs)
			delete(paths, lhs)
		}
		return true
	})
	return Result{Tainted: tainted, Reasons: reasons, Paths: paths}
}

// extendPath builds the source-to-sink location chain for a tainted
// assignment n whose taint verdict came from referencing variable ref (empty
// when n is itself a direct source match or an opaque same-file-call
// summary — see assignmentTaintsLHS). Returns nil when ref is non-empty but
// dfg can't confirm ref's definition reaches n (e.g. across a branch this
// sprint's CFG doesn't thread through — see graph.NewCFG's doc comment):
// the flow-insensitive taint verdict is still trusted, but the precise path
// isn't extended past what the graph can confirm.
func extendPath(n *ir.IRNode, ref string, dfg *graph.DFG, paths map[string][]core.Location) []core.Location {
	if ref == "" {
		return []core.Location{n.Location}
	}
	if len(dfg.ReachingDefs[n.NodeID][ref]) == 0 {
		return nil
	}
	prefix := paths[ref]
	path := make([]core.Location, len(prefix), len(prefix)+1)
	copy(path, prefix)
	return append(path, n.Location)
}

// assignmentTaintsLHS computes the fresh taint verdict for one assignment,
// a human-readable reason for a true verdict (empty for false), and the
// upstream tainted identifier name it propagated from, if any (empty for a
// direct source match, a summarized-call verdict, or a false verdict).
func assignmentTaintsLHS(n *ir.IRNode, pats languagePatterns, summaries map[string]functionSummary, symbols symboltable.SymbolTable, tainted map[string]bool) (bool, string, string) {
	rhs, _ := n.Attrs["rhs"].(string)
	if matchesAny(pats.Sanitizers, rhs) {
		return false, "", ""
	}
	if matchesAny(pats.Sources, rhs) {
		return true, rhs, ""
	}
	if ref, ok := rhsReferencesTainted(n, tainted); ok {
		return true, "propagated from " + ref, ref
	}
	if callee, ok := callTaintedViaSummary(n, summaries, symbols, tainted); ok {
		return true, "tainted via " + callee + "(...)", ""
	}
	return false, "", ""
}

// rhsReferencesTainted reports whether the assignment's right-hand-side
// subtree contains an identifier already known to be tainted, and if so,
// that identifier's name.
func rhsReferencesTainted(assignment *ir.IRNode, tainted map[string]bool) (string, bool) {
	if len(assignment.Children) == 0 {
		return "", false
	}
	rhsNode := assignment.Children[len(assignment.Children)-1]
	if rhsNode.Kind == ir.NodeKindIdentifier && tainted[rhsNode.Text] {
		return rhsNode.Text, true
	}
	for _, d := range ir.Descendants(rhsNode) {
		if d.Kind == ir.NodeKindIdentifier && tainted[d.Text] {
			return d.Text, true
		}
	}
	return "", false
}

// callTaintedViaSummary reports whether the assignment's RHS is a call to a
// same-file function whose summary marks the result tainted: alwaysTainted
// unconditionally, or passesThroughParam when at least one call argument is
// itself tainted. The callee must resolve to a locally defined function via
// the symbol table — imported or stdlib names are ignored. When true, also
// returns the callee's name.
func callTaintedViaSummary(assignment *ir.IRNode, summaries map[string]functionSummary, symbols symboltable.SymbolTable, tainted map[string]bool) (string, bool) {
	if len(summaries) == 0 || symbols == nil || len(assignment.Children) == 0 {
		return "", false
	}
	call := assignment.Children[len(assignment.Children)-1]
	if call.Kind != ir.NodeKindCall {
		return "", false
	}
	name := simpleCalleeName(call)
	if name == "" {
		return "", false
	}
	sum, ok := summaries[name]
	if !ok {
		return "", false
	}
	scope := symbols.ScopeAt(assignment.Location)
	sym, found := symbols.Resolve(name, scope.ID)
	if !found || sym.Kind != symboltable.SymbolFunction {
		return "", false
	}
	if sum.alwaysTainted {
		return name, true
	}
	if sum.passesThroughParam && anyCallArgTainted(call, tainted) {
		return name, true
	}
	return "", false
}

// simpleCalleeName extracts a plain-identifier callee (helper(...)); calls
// through attributes (obj.method(...)) are not same-file functions and
// return "".
func simpleCalleeName(call *ir.IRNode) string {
	for _, c := range call.Children {
		switch c.Kind {
		case ir.NodeKindIdentifier:
			return c.Text
		case ir.NodeKindAttribute:
			return ""
		}
	}
	return ""
}

// anyCallArgTainted reports whether any identifier in the call's argument
// subtrees (everything after the callee child) is tainted.
func anyCallArgTainted(call *ir.IRNode, tainted map[string]bool) bool {
	if len(call.Children) < 2 {
		return false
	}
	for _, argRoot := range call.Children[1:] {
		if argRoot.Kind == ir.NodeKindIdentifier && tainted[argRoot.Text] {
			return true
		}
		for _, d := range ir.Descendants(argRoot) {
			if d.Kind == ir.NodeKindIdentifier && tainted[d.Text] {
				return true
			}
		}
	}
	return false
}
