// Package taint performs a lightweight, file-scoped, intra-procedural taint
// pass over Python, JavaScript, and TypeScript IR. It exists to reduce false
// positives on injection rules that previously fired on any call to a sink
// function, regardless of whether the argument actually came from untrusted
// input.
package taint

import (
	"regexp"

	"github.com/zerostrike/scanner/internal/ir"
)

// sourcePattern matches right-hand-side expression text known to originate
// from untrusted input: Python (Flask/Django request objects, stdlib input
// sources) and JavaScript/TypeScript (Express request objects, browser
// location).
var sourcePattern = regexp.MustCompile(`request\.(args|form|GET|POST|values)|(^|\W)input\(|sys\.argv|os\.environ\.get|req\.(query|body|params)|location\.(search|hash)|window\.location`)

// Build walks file in source order and returns the set of variable names
// whose value may originate from an untrusted source.
//
// ponytail: taint is tracked per file, not per function scope — two functions
// reusing a variable name could cross-contaminate taint state. This is the
// simplest thing that catches the common case (a request param flowing into
// a sink a few lines later); scope per ir.NodeKindFunction subtree if false
// positives from this show up in practice.
func Build(file *ir.IRFile) map[string]bool {
	tainted := make(map[string]bool)
	if file == nil || file.Root == nil {
		return tainted
	}
	ir.Walk(file.Root, func(n *ir.IRNode) bool {
		if n.Kind != ir.NodeKindAssignment {
			return true
		}
		lhs, _ := n.Attrs["lhs"].(string)
		if lhs == "" {
			return true
		}
		rhs, _ := n.Attrs["rhs"].(string)
		if sourcePattern.MatchString(rhs) || rhsReferencesTainted(n, tainted) {
			tainted[lhs] = true
		}
		return true
	})
	return tainted
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
