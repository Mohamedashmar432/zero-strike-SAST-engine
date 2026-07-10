package graph_test

import (
	"testing"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/graph"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/ir"
)

// node is a small builder for hand-constructed IR fixtures: real IR nodes
// carry a UUID NodeID, but tests just need distinct, readable IDs.
func node(id string, kind ir.NodeKind, children ...*ir.IRNode) *ir.IRNode {
	return &ir.IRNode{NodeID: id, Kind: kind, Children: children}
}

func assign(id, lhs string) *ir.IRNode {
	n := node(id, ir.NodeKindAssignment)
	n.Attrs = map[string]any{"lhs": lhs}
	return n
}

func ident(id, text string) *ir.IRNode {
	n := node(id, ir.NodeKindIdentifier)
	n.Text = text
	return n
}

func TestNewCFG_NilRoot(t *testing.T) {
	if cfg := graph.NewCFG(nil); cfg != nil {
		t.Fatal("expected nil CFG for nil root")
	}
}

func TestNewCFG_StraightLine(t *testing.T) {
	root := node("mod", ir.NodeKindModule,
		assign("a1", "x"),
		assign("a2", "y"),
	)
	cfg := graph.NewCFG(root)
	if len(cfg.Nodes) != 3 {
		t.Fatalf("expected 3 nodes, got %d", len(cfg.Nodes))
	}
	// Sequential siblings under a Module fall through to the next statement.
	assertEdge(t, cfg, "a1", "a2", "normal")
}

func TestNewCFG_IfThenElse_DirectBlocks(t *testing.T) {
	thenBlock := node("then", ir.NodeKindBlock, assign("a1", "x"))
	elseBlock := node("else", ir.NodeKindBlock, assign("a2", "x"))
	ifNode := node("if1", ir.NodeKindIf, ident("cond", "flag"), thenBlock, elseBlock)

	cfg := graph.NewCFG(node("mod", ir.NodeKindModule, ifNode))

	assertEdge(t, cfg, "if1", "then", "true")
	assertEdge(t, cfg, "if1", "else", "false")
}

func TestNewCFG_IfElse_UnknownWrappedElseClause(t *testing.T) {
	// Mirrors the real tree-sitter shape: an else_clause (mapped to
	// NodeKindUnknown, since it has no dedicated NodeKind) wraps the actual
	// block rather than the block appearing as a direct child of the if.
	thenBlock := node("then", ir.NodeKindBlock, assign("a1", "x"))
	elseBlock := node("else-body", ir.NodeKindBlock, assign("a2", "x"))
	elseClauseWrapper := node("else-clause", ir.NodeKindUnknown, elseBlock)
	ifNode := node("if1", ir.NodeKindIf, ident("cond", "flag"), thenBlock, elseClauseWrapper)

	cfg := graph.NewCFG(node("mod", ir.NodeKindModule, ifNode))

	assertEdge(t, cfg, "if1", "then", "true")
	assertEdge(t, cfg, "if1", "else-body", "false")
}

func TestNewCFG_WhileLoop_HasLoopAndLoopBackEdges(t *testing.T) {
	body := node("body", ir.NodeKindBlock, assign("a1", "x"))
	loop := node("while1", ir.NodeKindWhile, ident("cond", "flag"), body)

	cfg := graph.NewCFG(node("mod", ir.NodeKindModule, loop))

	assertEdge(t, cfg, "while1", "body", "loop")
	assertEdge(t, cfg, "body", "while1", "loop-back")
}

func TestNewCFG_Try_EdgesToMainBody(t *testing.T) {
	body := node("try-body", ir.NodeKindBlock, assign("a1", "x"))
	tryNode := node("try1", ir.NodeKindTry, body)

	cfg := graph.NewCFG(node("mod", ir.NodeKindModule, tryNode))

	assertEdge(t, cfg, "try1", "try-body", "normal")
}

func TestNewCFG_IfElse_BothBranchesJoinAtNextStatement(t *testing.T) {
	// if flag: a1 = x else: a2 = x
	// a3 = y   <- reachable from BOTH branches' last statement, not from if1's header
	thenBlock := node("then", ir.NodeKindBlock, assign("a1", "x"))
	elseBlock := node("else", ir.NodeKindBlock, assign("a2", "x"))
	ifNode := node("if1", ir.NodeKindIf, ident("cond", "flag"), thenBlock, elseBlock)
	next := assign("a3", "y")

	cfg := graph.NewCFG(node("mod", ir.NodeKindModule, ifNode, next))

	assertEdge(t, cfg, "a1", "a3", "normal")
	assertEdge(t, cfg, "a2", "a3", "normal")
}

func TestNewCFG_IfNoElse_HeaderAndBranchBothJoinAtNextStatement(t *testing.T) {
	// if flag: a1 = x
	// a2 = y   <- reachable from a1 (true path) AND from if1 itself (false path, no else)
	thenBlock := node("then", ir.NodeKindBlock, assign("a1", "x"))
	ifNode := node("if1", ir.NodeKindIf, ident("cond", "flag"), thenBlock)
	next := assign("a2", "y")

	cfg := graph.NewCFG(node("mod", ir.NodeKindModule, ifNode, next))

	assertEdge(t, cfg, "a1", "a2", "normal")
	assertEdge(t, cfg, "if1", "a2", "normal")
}

func TestNewCFG_NestedIf_ExitsRecurseThroughBothLevels(t *testing.T) {
	// if outerFlag:
	//     if innerFlag: inner-a1 = x else: inner-a2 = x
	// else:
	//     outer-a2 = x
	// next = y   <- reachable from inner-a1, inner-a2, and outer-a2
	innerThen := node("inner-then", ir.NodeKindBlock, assign("inner-a1", "x"))
	innerElse := node("inner-else", ir.NodeKindBlock, assign("inner-a2", "x"))
	innerIf := node("inner-if", ir.NodeKindIf, ident("inner-cond", "innerFlag"), innerThen, innerElse)
	outerThen := node("outer-then", ir.NodeKindBlock, innerIf)
	outerElse := node("outer-else", ir.NodeKindBlock, assign("outer-a2", "x"))
	outerIf := node("outer-if", ir.NodeKindIf, ident("outer-cond", "outerFlag"), outerThen, outerElse)
	next := assign("next", "y")

	cfg := graph.NewCFG(node("mod", ir.NodeKindModule, outerIf, next))

	assertEdge(t, cfg, "inner-a1", "next", "normal")
	assertEdge(t, cfg, "inner-a2", "next", "normal")
	assertEdge(t, cfg, "outer-a2", "next", "normal")
}

func TestNewCFG_Try_JoinsFromLastBodyStatementNotHeader(t *testing.T) {
	body := node("try-body", ir.NodeKindBlock, assign("a1", "x"), assign("a2", "x"))
	tryNode := node("try1", ir.NodeKindTry, body)
	next := assign("a3", "y")

	cfg := graph.NewCFG(node("mod", ir.NodeKindModule, tryNode, next))

	assertEdge(t, cfg, "a2", "a3", "normal")
}

func TestNewCFG_Return_EdgesToImplicitExit(t *testing.T) {
	ret := node("ret1", ir.NodeKindReturn)
	cfg := graph.NewCFG(node("mod", ir.NodeKindModule, ret))

	found := false
	for _, e := range cfg.Nodes["ret1"].OutEdges {
		if e.Kind == "return" && e.To == "" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected a return edge with empty To (implicit exit)")
	}
}

func TestNewDFG_NilInputs(t *testing.T) {
	if dfg := graph.NewDFG(nil, &graph.CFG{}); dfg != nil {
		t.Fatal("expected nil DFG for nil root")
	}
	if dfg := graph.NewDFG(&ir.IRNode{}, nil); dfg != nil {
		t.Fatal("expected nil DFG for nil cfg")
	}
}

func TestNewDFG_StraightLineChain_ReachingDefsPropagate(t *testing.T) {
	// x = source(); y = x; z = y  — a straight-line taint chain, same shape
	// as the corpus SQL-injection fixture: each assignment's RHS references
	// the previous assignment's LHS.
	a1 := assign("a1", "x")
	a1.Children = []*ir.IRNode{ident("a1-rhs", "source")}
	a2 := assign("a2", "y")
	a2.Children = []*ir.IRNode{ident("a2-rhs", "x")}
	a3 := assign("a3", "z")
	a3.Children = []*ir.IRNode{ident("a3-rhs", "y")}

	root := node("mod", ir.NodeKindModule, a1, a2, a3)
	cfg := graph.NewCFG(root)
	dfg := graph.NewDFG(root, cfg)

	if got := dfg.Defs["x"]; len(got) != 1 || got[0] != "a1" {
		t.Errorf("Defs[x] = %v, want [a1]", got)
	}

	reachingAtA2 := dfg.ReachingDefs["a2"]
	if got := reachingAtA2["x"]; len(got) != 1 || got[0] != "a1" {
		t.Errorf("ReachingDefs[a2][x] = %v, want [a1] (a1 defines x, straight-line predecessor of a2)", got)
	}

	reachingAtA3 := dfg.ReachingDefs["a3"]
	if got := reachingAtA3["y"]; len(got) != 1 || got[0] != "a2" {
		t.Errorf("ReachingDefs[a3][y] = %v, want [a2]", got)
	}
	// x's definition should still be live at a3 too (nothing killed it).
	if got := reachingAtA3["x"]; len(got) != 1 || got[0] != "a1" {
		t.Errorf("ReachingDefs[a3][x] = %v, want [a1] (still live, never redefined)", got)
	}
}

func TestNewDFG_Reassignment_KillsPriorDef(t *testing.T) {
	a1 := assign("a1", "x") // x = "safe"
	a2 := assign("a2", "x") // x = "safe again" — redefines x, kills a1's reach
	a3 := assign("a3", "y")
	a3.Children = []*ir.IRNode{ident("a3-rhs", "x")}

	root := node("mod", ir.NodeKindModule, a1, a2, a3)
	cfg := graph.NewCFG(root)
	dfg := graph.NewDFG(root, cfg)

	reachingAtA3 := dfg.ReachingDefs["a3"]
	got := reachingAtA3["x"]
	if len(got) != 1 || got[0] != "a2" {
		t.Errorf("ReachingDefs[a3][x] = %v, want [a2] (a2 killed a1's definition)", got)
	}
}

func TestDFG_Location_ResolvesNodeID(t *testing.T) {
	a1 := assign("a1", "x")
	root := node("mod", ir.NodeKindModule, a1)
	cfg := graph.NewCFG(root)
	dfg := graph.NewDFG(root, cfg)

	got, ok := dfg.Location("a1")
	if !ok {
		t.Fatal("expected Location to resolve NodeID a1")
	}
	if got.NodeID != "a1" {
		t.Errorf("Location returned NodeID %q, want a1", got.NodeID)
	}

	if _, ok := dfg.Location("does-not-exist"); ok {
		t.Error("expected Location to report not-found for an unknown NodeID")
	}
}

func assertEdge(t *testing.T, cfg *graph.CFG, from, to, kind string) {
	t.Helper()
	fromNode := cfg.Nodes[from]
	if fromNode == nil {
		t.Fatalf("no CFG node for %q", from)
	}
	for _, e := range fromNode.OutEdges {
		if e.To == to && e.Kind == kind {
			return
		}
	}
	t.Errorf("expected edge %s -[%s]-> %s, out edges were: %v", from, kind, to, fromNode.OutEdges)
}
