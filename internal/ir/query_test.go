package ir

import (
	"testing"
)

// makeTree builds a small hand-constructed IR tree for testing.
//
//	module (root)
//	  function_def "foo"
//	    block
//	      call "eval_call"
//	        identifier "eval"
//	  class_def "Bar"
//	    block
//	      assignment "x"
func makeTree() *IRNode {
	root := &IRNode{Kind: NodeKindModule, Text: "root"}

	fn := &IRNode{Kind: NodeKindFunction, Text: "foo", Parent: root}
	fnBlock := &IRNode{Kind: NodeKindBlock, Text: "", Parent: fn}
	callNode := &IRNode{Kind: NodeKindCall, Text: "eval_call", Parent: fnBlock}
	calleeIdent := &IRNode{Kind: NodeKindIdentifier, Text: "eval", Parent: callNode}
	callNode.Children = []*IRNode{calleeIdent}
	fnBlock.Children = []*IRNode{callNode}
	fn.Children = []*IRNode{fnBlock}

	cls := &IRNode{Kind: NodeKindClass, Text: "Bar", Parent: root}
	clsBlock := &IRNode{Kind: NodeKindBlock, Text: "", Parent: cls}
	assign := &IRNode{Kind: NodeKindAssignment, Text: "x", Parent: clsBlock}
	clsBlock.Children = []*IRNode{assign}
	cls.Children = []*IRNode{clsBlock}

	root.Children = []*IRNode{fn, cls}
	return root
}

func TestWalk_VisitsAllNodes(t *testing.T) {
	root := makeTree()
	var visited []string
	Walk(root, func(node *IRNode) bool {
		visited = append(visited, string(node.Kind))
		return true
	})

	// Expected DFS pre-order: module, function_def, block, call, identifier, class_def, block, assignment
	expected := []string{
		"module", "function_def", "block", "call", "identifier", "class_def", "block", "assignment",
	}
	if len(visited) != len(expected) {
		t.Fatalf("expected %d nodes visited, got %d: %v", len(expected), len(visited), visited)
	}
	for i, e := range expected {
		if visited[i] != e {
			t.Errorf("position %d: expected %q, got %q", i, e, visited[i])
		}
	}
}

func TestWalk_StopsOnFalse(t *testing.T) {
	root := makeTree()
	var visited []string
	Walk(root, func(node *IRNode) bool {
		visited = append(visited, string(node.Kind))
		// Stop descending into function_def's subtree
		if node.Kind == NodeKindFunction {
			return false
		}
		return true
	})

	// module, function_def (stop), class_def, block, assignment
	expected := []string{"module", "function_def", "class_def", "block", "assignment"}
	if len(visited) != len(expected) {
		t.Fatalf("expected %d nodes visited, got %d: %v", len(expected), len(visited), visited)
	}
	for i, e := range expected {
		if visited[i] != e {
			t.Errorf("position %d: expected %q, got %q", i, e, visited[i])
		}
	}
}

func TestFindByKind(t *testing.T) {
	root := makeTree()
	blocks := FindByKind(root, NodeKindBlock)
	if len(blocks) != 2 {
		t.Fatalf("expected 2 block nodes, got %d", len(blocks))
	}
	for _, b := range blocks {
		if b.Kind != NodeKindBlock {
			t.Errorf("expected NodeKindBlock, got %q", b.Kind)
		}
	}

	calls := FindByKind(root, NodeKindCall)
	if len(calls) != 1 {
		t.Fatalf("expected 1 call node, got %d", len(calls))
	}
}

func TestFindByText(t *testing.T) {
	root := makeTree()
	nodes := FindByText(root, "eval")
	if len(nodes) != 1 {
		t.Fatalf("expected 1 node with text 'eval', got %d", len(nodes))
	}
	if nodes[0].Kind != NodeKindIdentifier {
		t.Errorf("expected identifier kind, got %q", nodes[0].Kind)
	}

	// Text that doesn't exist
	none := FindByText(root, "nonexistent")
	if len(none) != 0 {
		t.Errorf("expected 0 results for nonexistent text, got %d", len(none))
	}
}

func TestAncestors(t *testing.T) {
	root := makeTree()
	// Find the identifier "eval" which is at depth 4: module > function_def > block > call > identifier
	var evalNode *IRNode
	Walk(root, func(node *IRNode) bool {
		if node.Kind == NodeKindIdentifier && node.Text == "eval" {
			evalNode = node
		}
		return true
	})
	if evalNode == nil {
		t.Fatal("eval identifier node not found")
	}

	ancestors := Ancestors(evalNode)
	// ancestors from immediate parent up: call, block, function_def, module
	expectedKinds := []NodeKind{NodeKindCall, NodeKindBlock, NodeKindFunction, NodeKindModule}
	if len(ancestors) != len(expectedKinds) {
		t.Fatalf("expected %d ancestors, got %d", len(expectedKinds), len(ancestors))
	}
	for i, k := range expectedKinds {
		if ancestors[i].Kind != k {
			t.Errorf("ancestor[%d]: expected %q, got %q", i, k, ancestors[i].Kind)
		}
	}
}

func TestDescendants(t *testing.T) {
	// Build a simple tree: root with 2 children each with 1 child = 4 descendants total
	root := &IRNode{Kind: NodeKindModule}
	c1 := &IRNode{Kind: NodeKindFunction, Parent: root}
	c2 := &IRNode{Kind: NodeKindClass, Parent: root}
	c1c1 := &IRNode{Kind: NodeKindBlock, Parent: c1}
	c2c1 := &IRNode{Kind: NodeKindBlock, Parent: c2}
	c1.Children = []*IRNode{c1c1}
	c2.Children = []*IRNode{c2c1}
	root.Children = []*IRNode{c1, c2}

	desc := Descendants(root)
	if len(desc) != 4 {
		t.Fatalf("expected 4 descendants, got %d", len(desc))
	}
	// root itself must not be in the list
	for _, d := range desc {
		if d == root {
			t.Error("root should not be in descendants")
		}
	}
}

func TestFindCalls_Found(t *testing.T) {
	root := makeTree()
	calls := FindCalls(root, "eval")
	if len(calls) != 1 {
		t.Fatalf("expected 1 call to 'eval', got %d", len(calls))
	}
	if calls[0].Kind != NodeKindCall {
		t.Errorf("expected call node kind, got %q", calls[0].Kind)
	}
}

func TestFindCalls_NotFound(t *testing.T) {
	root := makeTree()
	calls := FindCalls(root, "exec")
	if len(calls) != 0 {
		t.Errorf("expected 0 calls to 'exec', got %d", len(calls))
	}
}
