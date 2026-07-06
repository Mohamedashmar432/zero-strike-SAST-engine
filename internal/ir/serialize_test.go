package ir_test

import (
	"encoding/json"
	"testing"

	"github.com/zerostrike/scanner/internal/core"
	"github.com/zerostrike/scanner/internal/ir"
)

// buildSampleTree constructs a representative hand-built IR tree exercising
// every Attrs type in the known-keys table, including all 3 problem types
// (argument_count, parameters, except_handlers). The tree has real depth
// (root with multiple children, one of which has its own children) so
// pre-order ordering bugs would actually be revealed by index checks.
//
// Shape:
//
//	module (root)
//	├── function_def "foo"          Attrs: parameters=[]string{"a","b"}
//	│   └── call "eval"             Attrs: argument_count=2, function_name="eval"
//	│       └── identifier "eval"
//	└── try                         Attrs: except_handlers=[]ir.ExceptHandler{...}
func buildSampleTree() *ir.IRFile {
	identNode := &ir.IRNode{
		NodeID: "n-ident",
		Kind:   ir.NodeKindIdentifier,
		Text:   "eval",
		Location: core.Location{
			File: "sample.py", StartLine: 3, EndLine: 3, StartCol: 5, EndCol: 9,
		},
	}
	callNode := &ir.IRNode{
		NodeID:   "n-call",
		Kind:     ir.NodeKindCall,
		Text:     "eval(x, y)",
		Location: core.Location{File: "sample.py", StartLine: 3, EndLine: 3, StartCol: 0, EndCol: 10},
		Children: []*ir.IRNode{identNode},
		Attrs: map[string]any{
			"argument_count": 2,
			"function_name":  "eval",
		},
	}
	funcNode := &ir.IRNode{
		NodeID:   "n-func",
		Kind:     ir.NodeKindFunction,
		Text:     "foo",
		Location: core.Location{File: "sample.py", StartLine: 1, EndLine: 3, StartCol: 0, EndCol: 10},
		Children: []*ir.IRNode{callNode},
		Attrs: map[string]any{
			"parameters": []string{"a", "b"},
		},
	}
	tryNode := &ir.IRNode{
		NodeID:   "n-try",
		Kind:     ir.NodeKindTry,
		Text:     "try",
		Location: core.Location{File: "sample.py", StartLine: 5, EndLine: 8, StartCol: 0, EndCol: 1},
		Attrs: map[string]any{
			"except_handlers": []ir.ExceptHandler{
				{IsBare: false, Types: []string{"ValueError", "TypeError"}, IsEmptyBody: true},
				{IsBare: true},
			},
		},
	}
	root := &ir.IRNode{
		NodeID:   "n-root",
		Kind:     ir.NodeKindModule,
		Text:     "module",
		Location: core.Location{File: "sample.py", StartLine: 1, EndLine: 8, StartCol: 0, EndCol: 1},
		Children: []*ir.IRNode{funcNode, tryNode},
	}
	return &ir.IRFile{Language: core.LangPython, Path: "sample.py", Root: root}
}

// findByKind is a small test helper to locate a rebuilt node by Kind, since
// after RebuildIR node identity is via a fresh pointer per index.
func findByKind(root *ir.IRNode, kind ir.NodeKind) *ir.IRNode {
	var found *ir.IRNode
	ir.Walk(root, func(n *ir.IRNode) bool {
		if n.Kind == kind && found == nil {
			found = n
		}
		return true
	})
	return found
}

func TestFlattenIR_NilFile(t *testing.T) {
	if got := ir.FlattenIR(nil); got != nil {
		t.Errorf("FlattenIR(nil) = %v, want nil", got)
	}
}

func TestFlattenIR_NilRoot(t *testing.T) {
	file := &ir.IRFile{Language: core.LangPython, Path: "x.py", Root: nil}
	if got := ir.FlattenIR(file); got != nil {
		t.Errorf("FlattenIR(file with nil Root) = %v, want nil", got)
	}
}

func TestRebuildIR_EmptySlice(t *testing.T) {
	if got := ir.RebuildIR(nil, core.LangPython, "x.py"); got != nil {
		t.Errorf("RebuildIR(nil) = %v, want nil", got)
	}
	if got := ir.RebuildIR([]ir.SerialNode{}, core.LangPython, "x.py"); got != nil {
		t.Errorf("RebuildIR([]) = %v, want nil", got)
	}
}

// TestFlattenIR_RootIsIndexZero verifies index 0 of FlattenIR's output is
// always the root, using a tree with real depth (multiple children, one
// with its own children) so a pre-order bug would actually be revealed.
func TestFlattenIR_RootIsIndexZero(t *testing.T) {
	file := buildSampleTree()
	flat := ir.FlattenIR(file)

	if len(flat) != 5 {
		t.Fatalf("expected 5 flattened nodes, got %d", len(flat))
	}
	if flat[0].Kind != ir.NodeKindModule || flat[0].NodeID != "n-root" {
		t.Fatalf("expected index 0 to be the root module node, got %+v", flat[0])
	}
	// Pre-order: root, func, call, ident, try
	wantOrder := []ir.NodeKind{
		ir.NodeKindModule, ir.NodeKindFunction, ir.NodeKindCall,
		ir.NodeKindIdentifier, ir.NodeKindTry,
	}
	for i, want := range wantOrder {
		if flat[i].Kind != want {
			t.Errorf("index %d: got kind %s, want %s", i, flat[i].Kind, want)
		}
	}
	// Root's Children should reference func (index 1) and try (index 4).
	if len(flat[0].Children) != 2 || flat[0].Children[0] != 1 || flat[0].Children[1] != 4 {
		t.Errorf("root children indices = %v, want [1 4]", flat[0].Children)
	}
}

// TestRoundTrip_ThroughJSON is the critical test: it flattens a hand-built
// tree, marshals it through encoding/json, unmarshals into a fresh slice,
// rebuilds the tree, and asserts both structure and the 3 problem-type
// Attrs keys type-assert correctly with correct values on the far side.
// This is the test that would have caught a naive JSON round-trip losing
// int/[]string/[]ir.ExceptHandler shapes.
func TestRoundTrip_ThroughJSON(t *testing.T) {
	original := buildSampleTree()
	flat := ir.FlattenIR(original)

	data, err := json.Marshal(flat)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var roundTripped []ir.SerialNode
	if err := json.Unmarshal(data, &roundTripped); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	rebuilt := ir.RebuildIR(roundTripped, core.LangPython, "sample.py")
	if rebuilt == nil {
		t.Fatal("RebuildIR returned nil")
	}
	if rebuilt.Language != core.LangPython {
		t.Errorf("Language = %v, want LangPython", rebuilt.Language)
	}
	if rebuilt.Path != "sample.py" {
		t.Errorf("Path = %q, want sample.py", rebuilt.Path)
	}
	if rebuilt.Root == nil {
		t.Fatal("rebuilt.Root is nil")
	}

	// Structure checks: kind/text/location for root, and full parent-child
	// wiring for every non-root node.
	root := rebuilt.Root
	if root.Kind != ir.NodeKindModule || root.Text != "module" || root.NodeID != "n-root" {
		t.Errorf("root mismatch: %+v", root)
	}
	if root.Parent != nil {
		t.Errorf("root.Parent should be nil, got %+v", root.Parent)
	}
	if len(root.Children) != 2 {
		t.Fatalf("root should have 2 children, got %d", len(root.Children))
	}

	funcNode := root.Children[0]
	tryNode := root.Children[1]

	if funcNode.Kind != ir.NodeKindFunction || funcNode.NodeID != "n-func" {
		t.Errorf("funcNode mismatch: %+v", funcNode)
	}
	if funcNode.Parent != root {
		t.Errorf("funcNode.Parent should point back to root")
	}
	if funcNode.Location.File != "sample.py" || funcNode.Location.StartLine != 1 || funcNode.Location.EndCol != 10 {
		t.Errorf("funcNode.Location mismatch: %+v", funcNode.Location)
	}

	if tryNode.Kind != ir.NodeKindTry || tryNode.NodeID != "n-try" {
		t.Errorf("tryNode mismatch: %+v", tryNode)
	}
	if tryNode.Parent != root {
		t.Errorf("tryNode.Parent should point back to root")
	}

	if len(funcNode.Children) != 1 {
		t.Fatalf("funcNode should have 1 child, got %d", len(funcNode.Children))
	}
	callNode := funcNode.Children[0]
	if callNode.Kind != ir.NodeKindCall || callNode.NodeID != "n-call" {
		t.Errorf("callNode mismatch: %+v", callNode)
	}
	if callNode.Parent != funcNode {
		t.Errorf("callNode.Parent should point back to funcNode")
	}

	if len(callNode.Children) != 1 {
		t.Fatalf("callNode should have 1 child, got %d", len(callNode.Children))
	}
	identNode := callNode.Children[0]
	if identNode.Kind != ir.NodeKindIdentifier || identNode.Text != "eval" {
		t.Errorf("identNode mismatch: %+v", identNode)
	}
	if identNode.Parent != callNode {
		t.Errorf("identNode.Parent should point back to callNode")
	}

	// THE critical assertions: the 3 problem-type Attrs keys must
	// type-assert to their correct concrete Go types after the JSON hop.
	ac, ok := callNode.Attrs["argument_count"].(int)
	if !ok {
		t.Fatalf("callNode.Attrs[\"argument_count\"] failed to type-assert to int; got %T", callNode.Attrs["argument_count"])
	}
	if ac != 2 {
		t.Errorf("argument_count = %d, want 2", ac)
	}

	params, ok := funcNode.Attrs["parameters"].([]string)
	if !ok {
		t.Fatalf("funcNode.Attrs[\"parameters\"] failed to type-assert to []string; got %T", funcNode.Attrs["parameters"])
	}
	if len(params) != 2 || params[0] != "a" || params[1] != "b" {
		t.Errorf("parameters = %v, want [a b]", params)
	}

	handlers, ok := tryNode.Attrs["except_handlers"].([]ir.ExceptHandler)
	if !ok {
		t.Fatalf("tryNode.Attrs[\"except_handlers\"] failed to type-assert to []ir.ExceptHandler; got %T", tryNode.Attrs["except_handlers"])
	}
	if len(handlers) != 2 {
		t.Fatalf("expected 2 except handlers, got %d", len(handlers))
	}
	if handlers[0].IsBare != false || len(handlers[0].Types) != 2 || handlers[0].Types[0] != "ValueError" || handlers[0].Types[1] != "TypeError" || !handlers[0].IsEmptyBody {
		t.Errorf("handlers[0] mismatch: %+v", handlers[0])
	}
	if !handlers[1].IsBare || len(handlers[1].Types) != 0 || handlers[1].IsEmptyBody {
		t.Errorf("handlers[1] mismatch: %+v", handlers[1])
	}

	// Sanity check for a safe string-typed Attrs key too.
	fn, ok := callNode.Attrs["function_name"].(string)
	if !ok || fn != "eval" {
		t.Errorf("function_name = %v (ok=%v), want eval", callNode.Attrs["function_name"], ok)
	}
}

// TestRebuildIR_WithoutJSONHop verifies RebuildIR(FlattenIR(tree), ...)
// works directly, Go-to-Go, without ever touching encoding/json — this
// exercises the "already correct concrete type, don't double-convert"
// path in restoreAttrs.
func TestRebuildIR_WithoutJSONHop(t *testing.T) {
	original := buildSampleTree()
	flat := ir.FlattenIR(original)
	rebuilt := ir.RebuildIR(flat, core.LangPython, "sample.py")

	if rebuilt == nil || rebuilt.Root == nil {
		t.Fatal("RebuildIR returned nil or nil Root")
	}

	callNode := findByKind(rebuilt.Root, ir.NodeKindCall)
	if callNode == nil {
		t.Fatal("could not find call node in rebuilt tree")
	}
	ac, ok := callNode.Attrs["argument_count"].(int)
	if !ok || ac != 2 {
		t.Errorf("argument_count (no JSON hop) = %v (ok=%v), want 2", callNode.Attrs["argument_count"], ok)
	}

	funcNode := findByKind(rebuilt.Root, ir.NodeKindFunction)
	if funcNode == nil {
		t.Fatal("could not find function node in rebuilt tree")
	}
	params, ok := funcNode.Attrs["parameters"].([]string)
	if !ok || len(params) != 2 {
		t.Errorf("parameters (no JSON hop) = %v (ok=%v), want [a b]", funcNode.Attrs["parameters"], ok)
	}

	tryNode := findByKind(rebuilt.Root, ir.NodeKindTry)
	if tryNode == nil {
		t.Fatal("could not find try node in rebuilt tree")
	}
	handlers, ok := tryNode.Attrs["except_handlers"].([]ir.ExceptHandler)
	if !ok || len(handlers) != 2 {
		t.Errorf("except_handlers (no JSON hop) = %v (ok=%v), want 2 handlers", tryNode.Attrs["except_handlers"], ok)
	}

	// Verify parent pointers are set correctly in the no-JSON-hop path too.
	if funcNode.Parent != rebuilt.Root {
		t.Errorf("funcNode.Parent should point to rebuilt root")
	}
	if callNode.Parent != funcNode {
		t.Errorf("callNode.Parent should point to funcNode")
	}
}

// TestFlattenIR_DoesNotAliasOriginalAttrs guards against a caller mutating a
// SerialNode's Attrs (e.g. on a cache-write path) silently corrupting the
// live IRNode tree still in use elsewhere in the same scan — FlattenIR must
// copy each node's Attrs map, not share the original's underlying storage.
func TestFlattenIR_DoesNotAliasOriginalAttrs(t *testing.T) {
	original := buildSampleTree()
	flat := ir.FlattenIR(original)

	callNode := findByKind(original.Root, ir.NodeKindCall)
	if callNode == nil {
		t.Fatal("could not find call node in original tree")
	}

	var flatCall *ir.SerialNode
	for i := range flat {
		if flat[i].Kind == ir.NodeKindCall {
			flatCall = &flat[i]
			break
		}
	}
	if flatCall == nil {
		t.Fatal("could not find call node in flattened slice")
	}

	// Mutate the flattened copy's Attrs map directly.
	flatCall.Attrs["argument_count"] = 999
	flatCall.Attrs["injected"] = "should not leak back"

	if ac, _ := callNode.Attrs["argument_count"].(int); ac != 2 {
		t.Errorf("mutating the flattened Attrs map changed the original tree's argument_count to %v, want unchanged 2", ac)
	}
	if _, present := callNode.Attrs["injected"]; present {
		t.Error("mutating the flattened Attrs map leaked a new key back into the original tree")
	}
}
