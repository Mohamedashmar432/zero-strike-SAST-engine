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
	"github.com/zerostrike/scanner/internal/ir"
	"github.com/zerostrike/scanner/internal/symboltable"
)

// Build walks file in source order and returns the set of variable names
// whose value may originate from an untrusted source. symbols is the file's
// already-built symbol table (used to confirm that a called function is
// locally defined before consulting its summary); it may be nil, which
// disables the same-file interprocedural step.
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
	tainted := make(map[string]bool)
	if file == nil || file.Root == nil {
		return tainted
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
		verdict := assignmentTaintsLHS(n, pats, summaries, symbols, tainted)
		if aug, _ := n.Attrs["augmented"].(bool); aug {
			verdict = verdict || tainted[lhs]
		}
		tainted[lhs] = verdict
		return true
	})
	return tainted
}

// assignmentTaintsLHS computes the fresh taint verdict for one assignment.
func assignmentTaintsLHS(n *ir.IRNode, pats languagePatterns, summaries map[string]functionSummary, symbols symboltable.SymbolTable, tainted map[string]bool) bool {
	rhs, _ := n.Attrs["rhs"].(string)
	if matchesAny(pats.Sanitizers, rhs) {
		return false
	}
	if matchesAny(pats.Sources, rhs) {
		return true
	}
	if rhsReferencesTainted(n, tainted) {
		return true
	}
	return callTaintedViaSummary(n, summaries, symbols, tainted)
}

// rhsReferencesTainted reports whether the assignment's right-hand-side
// subtree contains an identifier already known to be tainted.
func rhsReferencesTainted(assignment *ir.IRNode, tainted map[string]bool) bool {
	if len(assignment.Children) == 0 {
		return false
	}
	rhsNode := assignment.Children[len(assignment.Children)-1]
	if rhsNode.Kind == ir.NodeKindIdentifier && tainted[rhsNode.Text] {
		return true
	}
	for _, d := range ir.Descendants(rhsNode) {
		if d.Kind == ir.NodeKindIdentifier && tainted[d.Text] {
			return true
		}
	}
	return false
}

// callTaintedViaSummary reports whether the assignment's RHS is a call to a
// same-file function whose summary marks the result tainted: alwaysTainted
// unconditionally, or passesThroughParam when at least one call argument is
// itself tainted. The callee must resolve to a locally defined function via
// the symbol table — imported or stdlib names are ignored.
func callTaintedViaSummary(assignment *ir.IRNode, summaries map[string]functionSummary, symbols symboltable.SymbolTable, tainted map[string]bool) bool {
	if len(summaries) == 0 || symbols == nil || len(assignment.Children) == 0 {
		return false
	}
	call := assignment.Children[len(assignment.Children)-1]
	if call.Kind != ir.NodeKindCall {
		return false
	}
	name := simpleCalleeName(call)
	if name == "" {
		return false
	}
	sum, ok := summaries[name]
	if !ok {
		return false
	}
	scope := symbols.ScopeAt(assignment.Location)
	sym, found := symbols.Resolve(name, scope.ID)
	if !found || sym.Kind != symboltable.SymbolFunction {
		return false
	}
	if sum.alwaysTainted {
		return true
	}
	return sum.passesThroughParam && anyCallArgTainted(call, tainted)
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
