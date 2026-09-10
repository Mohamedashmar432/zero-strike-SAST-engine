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
	"strings"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/graph"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/ir"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/symboltable"
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

	// Weak marks tainted variables whose taint comes only from the
	// function-parameter seeding below, with no matched source pattern
	// anywhere upstream. It is a subset of Tainted.
	//
	// The distinction exists because parameter seeding is deliberately
	// imprecise: every parameter of every function is treated as untrusted so
	// that a handler-extracts/helper-executes split still reports (see the
	// seeding comment in BuildContext). That is right for a SQL sink, but on
	// its own it makes `setTimeout(cb, delay)`, `fetch(url)` and
	// `new RegExp(pattern)` fire on any ordinary helper that happens to take
	// an argument — which is where three of the six false-positive classes in
	// the triage of a real scan came from.
	//
	// Rules that are noisy under that assumption opt out with the
	// require_real_source filter, which demands a variable that is tainted and
	// NOT weak. Rules where parameter taint is the point (SQL, command
	// injection, path traversal) ignore Weak entirely and keep their recall.
	Weak map[string]bool
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
	weak := make(map[string]bool)
	if file == nil || file.Root == nil {
		return Result{Tainted: tainted, Reasons: reasons, Paths: paths, Weak: weak}
	}
	pats := patternsFor(file.Language)
	summaries := buildSummaries(file, pats)

	// Seed function parameters as tainted before walking assignments.
	//
	// Without this the engine only ever sees taint that both originates and
	// is consumed inside one function body, which is not how real code is
	// written: the request handler extracts the value and a helper does the
	// dangerous thing with it. dvpwa is the clean demonstration — 0 findings
	// across 40 files of a deliberately vulnerable SQL-injection app, because
	// every DAO takes its input as a parameter:
	//
	//     q = ("INSERT INTO students (name) VALUES ('%(name)s')" % {'name': name})
	//     await cur.execute(q)      # `name` is a bare parameter
	//
	// Seeding happens up front rather than per-scope because the taint map is
	// file-scoped and flow-insensitive (see Build's doc comment); a later
	// clean reassignment still clears the verdict, since the assignment walk
	// below runs afterwards and overwrites.
	//
	// ponytail: every parameter is seeded, not just those of request-handler
	// -shaped functions. Type-aware or entry-point-only seeding would be more
	// precise; this is the version whose cost is measurable against the
	// corpus's --max-fp 0 gate. Narrow it if that gate or the real-target
	// false-positive rate says to.
	ir.Walk(file.Root, func(n *ir.IRNode) bool {
		if n.Kind != ir.NodeKindFunction {
			return true
		}
		params, _ := n.Attrs["parameters"].([]string)
		for _, p := range params {
			if p == "" || p == "_" {
				continue
			}
			tainted[p] = true
			reasons[p] = "unvalidated function parameter " + p
			// Seeded taint with no source pattern behind it — see Result.Weak.
			weak[p] = true
		}
		return true
	})

	ir.Walk(file.Root, func(n *ir.IRNode) bool {
		if n.Kind != ir.NodeKindAssignment {
			return true
		}
		lhs, _ := n.Attrs["lhs"].(string)
		if lhs == "" {
			return true
		}
		verdict, reason, ref := assignmentTaintsLHS(n, pats, summaries, symbols, tainted)
		aug, _ := n.Attrs["augmented"].(bool)
		for _, name := range lhsNames(lhs) {
			v, rs, rf := verdict, reason, ref
			if aug && !v && tainted[name] {
				// Inherits the previous verdict; keep the previously
				// recorded reason instead of overwriting with empty.
				v, rs, rf = true, reasons[name], name
			}
			tainted[name] = v
			if v {
				// Weakness follows the same edge the verdict came from.
				// assignmentTaintsLHS returns a non-empty ref only when the
				// verdict was "RHS references an already-tainted name", so
				// ref != "" is exactly the propagation case and inherits that
				// name's tier. Everything else that yields true is a matched
				// source pattern or a function summary, both of which are
				// real sources, so the LHS becomes strong.
				if rf != "" {
					weak[name] = weak[rf]
				} else {
					delete(weak, name)
				}
				reasons[name] = rs
				if dfg != nil {
					if p := extendPath(n, rf, dfg, paths); p != nil {
						paths[name] = p
					} else {
						delete(paths, name)
					}
				}
			} else {
				delete(reasons, name)
				delete(paths, name)
				delete(weak, name)
			}
		}
		return true
	})
	return Result{Tainted: tainted, Reasons: reasons, Paths: paths, Weak: weak}
}

// lhsNames splits an assignment's LHS text into the individual variable names
// it binds.
//
// Builders store the whole `left` span as one Attrs["lhs"] string, so Go's
// `num, _ := strconv.Atoi(val)` and Python's `a, b = f()` both arrive here as
// the literal text "num, _" / "a, b". Keying taint on that verbatim loses the
// binding outright: a later reference to bare `num` never matches the key
// "num, _". Since `value, err := fn()` is Go's near-universal call idiom, that
// silently dropped taint across most real Go code — it is why ZS-GO-014
// (integer overflow) was authored, never fired, and was removed in Sprint 28
// instead of shipped, and why damn-vulnerable-golang's annotated CWE-190 case
// (`val := ...Query().Get("val"); num, _ := strconv.Atoi(val)`) went undetected.
//
// Only the taint map keys are split. Attrs["lhs"] is deliberately left intact
// so rules matching on lhs_identifier keep seeing the original source text.
func lhsNames(lhs string) []string {
	if !strings.Contains(lhs, ",") {
		return []string{lhs}
	}
	var out []string
	for _, p := range strings.Split(lhs, ",") {
		// "_" is Go's blank identifier — nothing can ever reference it back,
		// so a taint entry for it would only be dead weight in the map.
		if p = strings.TrimSpace(p); p != "" && p != "_" {
			out = append(out, p)
		}
	}
	return out
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
