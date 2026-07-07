package graph

import "github.com/zerostrike/scanner/internal/ir"

// CFGEdge is a directed control-flow edge between two IR nodes, identified by
// NodeID. Kind is one of "normal", "true", "false", "loop", "loop-back", or
// "return" (return has an empty To, meaning "exits the function").
type CFGEdge struct {
	From string
	To   string
	Kind string
}

// CFGNode is a single node's position in the control-flow graph: its NodeID
// plus the edges that touch it, split by direction for O(1) predecessor/
// successor lookups during dataflow analysis.
type CFGNode struct {
	NodeID   string
	InEdges  []CFGEdge
	OutEdges []CFGEdge
}

// CFG is a Control Flow Graph for a single file's IR tree. Every IR node
// becomes a CFGNode; edges connect branch/loop/try nodes to their bodies and
// return nodes to the (implicit) function exit.
type CFG struct {
	Nodes map[string]*CFGNode
}

// DFG is a Data Flow Graph tracking definition-use chains and, via
// ReachingDefs, which assignments may still be live (not overwritten) at
// each node — the basis for path-sensitive taint reporting.
type DFG struct {
	// Defs maps a variable name to the NodeIDs of every assignment that
	// defines it, in source order.
	Defs map[string][]string
	// Uses maps a variable name to the NodeIDs of every identifier reference
	// that reads it (including on the RHS of its own assignment).
	Uses map[string][]string
	// ReachingDefs maps a NodeID to, for each variable, the NodeIDs of the
	// definitions that may reach that point without being overwritten.
	ReachingDefs map[string]map[string][]string

	nodeByID map[string]*ir.IRNode
}

// CallGraph represents caller-callee relationships across functions.
// CallGraph deferred to a future sprint (needs two-phase scan); see
// docs/roadmap/SPRINT-22-GRAPH-LAYER-CFG-DFG.md.
type CallGraph struct{}

// Location resolves a NodeID (as found in Defs/Uses/ReachingDefs) back to the
// IR node's source location. Returns false if the NodeID is unknown.
func (d *DFG) Location(nodeID string) (ir.IRNode, bool) {
	n, ok := d.nodeByID[nodeID]
	if !ok || n == nil {
		return ir.IRNode{}, false
	}
	return *n, true
}

// NewCFG builds a Control Flow Graph over root. Returns nil if root is nil.
//
// ponytail: the underlying tree-sitter-derived IR includes anonymous tokens
// (keywords, punctuation) as NodeKindUnknown children, and constructs like
// elif/else clauses are themselves wrapped in a NodeKindUnknown node rather
// than appearing as direct If-node children — so edges are found by
// searching for NodeKindBlock through at most one level of Unknown wrapper,
// not by indexing Children positionally. This is deliberately conservative:
// it finds true branch/loop/try bodies without assuming exact grammar shape,
// at the cost of not modeling individual except-handler bodies as distinct
// CFG targets (see the Try case below).
func NewCFG(root *ir.IRNode) *CFG {
	if root == nil {
		return nil
	}

	cfg := &CFG{Nodes: make(map[string]*CFGNode)}
	ir.Walk(root, func(n *ir.IRNode) bool {
		cfg.Nodes[n.NodeID] = &CFGNode{NodeID: n.NodeID}
		return true
	})

	addEdge := func(from, to, kind string) {
		if from == "" {
			return
		}
		edge := CFGEdge{From: from, To: to, Kind: kind}
		if fn := cfg.Nodes[from]; fn != nil {
			fn.OutEdges = append(fn.OutEdges, edge)
		}
		if to != "" {
			if tn := cfg.Nodes[to]; tn != nil {
				tn.InEdges = append(tn.InEdges, edge)
			}
		}
	}

	ir.Walk(root, func(n *ir.IRNode) bool {
		switch n.Kind {
		case ir.NodeKindIf:
			blocks := directOrWrappedBlocks(n)
			if len(blocks) > 0 {
				addEdge(n.NodeID, blocks[0].NodeID, "true")
			}
			for _, alt := range blocks[1:] {
				addEdge(n.NodeID, alt.NodeID, "false")
			}
		case ir.NodeKindFor, ir.NodeKindWhile:
			blocks := directOrWrappedBlocks(n)
			if len(blocks) > 0 {
				body := blocks[0]
				addEdge(n.NodeID, body.NodeID, "loop")
				addEdge(body.NodeID, n.NodeID, "loop-back")
			}
		case ir.NodeKindTry:
			// Only the main try body is modeled as a CFG target; individual
			// except-handler bodies aren't addressable IR nodes today (see
			// ir.ExceptHandler — it carries no node reference), so exception
			// edges are deferred rather than guessed at.
			if blocks := directOrWrappedBlocks(n); len(blocks) > 0 {
				addEdge(n.NodeID, blocks[0].NodeID, "normal")
			}
		case ir.NodeKindReturn:
			addEdge(n.NodeID, "", "return")
		}
		return true
	})

	// Sequential fall-through: statements directly inside a Module or Block
	// execute one after another. A Return statement's own out-edge already
	// goes to the implicit exit, so it doesn't also fall through.
	//
	// ponytail: this connects a branch/loop *header* node to the next
	// sibling, not each branch's last inner statement — so a definition made
	// only inside one arm of an if isn't seen as reaching the code after the
	// if. Full block-exit-point threading would fix that; not needed for the
	// straight-line and single-branch taint chains this sprint targets.
	ir.Walk(root, func(n *ir.IRNode) bool {
		if n.Kind != ir.NodeKindModule && n.Kind != ir.NodeKindBlock {
			return true
		}
		for i := 0; i+1 < len(n.Children); i++ {
			cur, next := n.Children[i], n.Children[i+1]
			if cur.Kind == ir.NodeKindReturn {
				continue
			}
			addEdge(cur.NodeID, next.NodeID, "normal")
		}
		return true
	})

	return cfg
}

// directOrWrappedBlocks returns every NodeKindBlock found either as a direct
// child of n, or as a child of an immediate NodeKindUnknown child of n (the
// shape an elif_clause/else_clause takes in this IR), in source order.
func directOrWrappedBlocks(n *ir.IRNode) []*ir.IRNode {
	var blocks []*ir.IRNode
	for _, c := range n.Children {
		switch c.Kind {
		case ir.NodeKindBlock:
			blocks = append(blocks, c)
		case ir.NodeKindUnknown:
			for _, gc := range c.Children {
				if gc.Kind == ir.NodeKindBlock {
					blocks = append(blocks, gc)
				}
			}
		}
	}
	return blocks
}

// NewDFG builds a Data Flow Graph over root, using cfg for reaching-
// definitions analysis. Returns nil if root or cfg is nil.
func NewDFG(root *ir.IRNode, cfg *CFG) *DFG {
	if root == nil || cfg == nil {
		return nil
	}

	dfg := &DFG{
		Defs:         make(map[string][]string),
		Uses:         make(map[string][]string),
		ReachingDefs: make(map[string]map[string][]string),
		nodeByID:     make(map[string]*ir.IRNode),
	}

	var order []*ir.IRNode
	ir.Walk(root, func(n *ir.IRNode) bool {
		order = append(order, n)
		dfg.nodeByID[n.NodeID] = n
		return true
	})

	for _, n := range order {
		if n.Kind != ir.NodeKindAssignment {
			continue
		}
		if lhs, ok := n.Attrs["lhs"].(string); ok && lhs != "" {
			dfg.Defs[lhs] = append(dfg.Defs[lhs], n.NodeID)
		}
	}
	for _, n := range order {
		if n.Kind == ir.NodeKindIdentifier && n.Text != "" {
			dfg.Uses[n.Text] = append(dfg.Uses[n.Text], n.NodeID)
		}
	}

	computeReachingDefs(order, cfg, dfg)
	return dfg
}

// computeReachingDefs runs a standard forward reaching-definitions
// fixed-point analysis: out[n] = gen[n] ∪ (in[n] - kill[n]), where gen[n] is
// "n defines this variable" and kill[n] is "n redefines every other def of
// the same variable". in[n] is the union of out[] over n's CFG predecessors.
//
// ponytail: iterates to a fixed point over the whole node set on every
// change, so it's worst-case O(n^2) on deeply nested loops; fine at rule/file
// scale, revisit with a worklist queue if it ever shows up in profiles.
func computeReachingDefs(order []*ir.IRNode, cfg *CFG, dfg *DFG) {
	// defsOf[varName] = every NodeID that defines it — used to compute kill
	// sets (every other definition of the same variable a node's def kills).
	defsOf := dfg.Defs

	out := make(map[string]map[string]bool, len(order)) // nodeID -> defNodeID -> reaches
	for _, n := range order {
		out[n.NodeID] = make(map[string]bool)
	}

	changed := true
	for changed {
		changed = false
		for _, n := range order {
			in := make(map[string]bool)
			if cn := cfg.Nodes[n.NodeID]; cn != nil {
				for _, e := range cn.InEdges {
					for defID := range out[e.From] {
						in[defID] = true
					}
				}
			}

			next := make(map[string]bool, len(in))
			for defID := range in {
				next[defID] = true
			}
			if lhs, ok := n.Attrs["lhs"].(string); ok && lhs != "" {
				for _, otherDef := range defsOf[lhs] {
					delete(next, otherDef) // kill: this assignment overwrites every prior def of lhs
				}
				next[n.NodeID] = true // gen: this assignment is now the reaching def of lhs
			}

			if !sameSet(next, out[n.NodeID]) {
				out[n.NodeID] = next
				changed = true
			}
		}
	}

	// ReachingDefs[n] is what's live entering n, i.e. the union of
	// predecessors' out sets (root/no-predecessor nodes see nothing yet).
	for _, n := range order {
		reaching := make(map[string][]string)
		if cn := cfg.Nodes[n.NodeID]; cn != nil {
			for _, e := range cn.InEdges {
				for defID := range out[e.From] {
					if defNode, ok := dfg.nodeByID[defID]; ok {
						if lhs, ok := defNode.Attrs["lhs"].(string); ok && lhs != "" {
							reaching[lhs] = append(reaching[lhs], defID)
						}
					}
				}
			}
		}
		dfg.ReachingDefs[n.NodeID] = reaching
	}
}

func sameSet(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}
