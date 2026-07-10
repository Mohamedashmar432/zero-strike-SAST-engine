package analyzer_test

import (
	"context"
	"testing"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/analyzer"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/ir"
)

func TestAnalyze_PopulatesResult(t *testing.T) {
	irFile := &ir.IRFile{
		Language: core.LangPython,
		Path:     "test.py",
		Root: &ir.IRNode{
			Kind:     ir.NodeKindModule,
			Location: core.Location{StartLine: 1, EndLine: 5},
			Attrs:    map[string]any{},
		},
	}

	result, err := analyzer.New(false).Analyze(context.Background(), irFile)
	if err != nil {
		t.Fatalf("Analyze returned error: %v", err)
	}
	if result == nil {
		t.Fatal("result is nil")
	}
	if result.IR != irFile {
		t.Error("result.IR does not point to input IRFile")
	}
	if result.Symbols == nil {
		t.Error("result.Symbols is nil")
	}
	if result.File != "test.py" {
		t.Errorf("result.File = %q, want test.py", result.File)
	}
	if len(result.Diagnostics) != 0 {
		t.Errorf("expected no diagnostics on valid file, got %d", len(result.Diagnostics))
	}
}

func TestAnalyze_NilIRFile(t *testing.T) {
	result, err := analyzer.New(false).Analyze(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("result is nil")
	}
}

func pythonFile(root *ir.IRNode) *ir.IRFile {
	return &ir.IRFile{Language: core.LangPython, Path: "test.py", Root: root}
}

func TestAnalyze_GraphsDisabled_CFGAndDFGStayNil(t *testing.T) {
	root := &ir.IRNode{Kind: ir.NodeKindModule}
	result, err := analyzer.New(false).Analyze(context.Background(), pythonFile(root))
	if err != nil {
		t.Fatalf("Analyze returned error: %v", err)
	}
	if result.CFG != nil || result.DFG != nil {
		t.Errorf("expected CFG and DFG nil with enableGraphs=false, got CFG=%v DFG=%v", result.CFG, result.DFG)
	}
}

func TestAnalyze_GraphsEnabled_PythonPopulatesCFGAndDFG(t *testing.T) {
	root := &ir.IRNode{Kind: ir.NodeKindModule}
	result, err := analyzer.New(true).Analyze(context.Background(), pythonFile(root))
	if err != nil {
		t.Fatalf("Analyze returned error: %v", err)
	}
	if result.CFG == nil {
		t.Error("expected CFG to be populated with enableGraphs=true for Python")
	}
	if result.DFG == nil {
		t.Error("expected DFG to be populated with enableGraphs=true for Python")
	}
}

func TestAnalyze_GraphsEnabled_NonPythonStaysNil(t *testing.T) {
	root := &ir.IRNode{Kind: ir.NodeKindModule}
	file := &ir.IRFile{Language: core.LangJavaScript, Path: "test.js", Root: root}
	result, err := analyzer.New(true).Analyze(context.Background(), file)
	if err != nil {
		t.Fatalf("Analyze returned error: %v", err)
	}
	if result.CFG != nil || result.DFG != nil {
		t.Error("expected CFG/DFG to stay nil for a non-Python language, even with enableGraphs=true")
	}
}

// TestAnalyze_GraphsEnabled_PopulatesTaintPathForChain mirrors a simple
// source-to-sink taint chain (x = source(); y = x) and checks that
// TaintPaths carries both hops when graphs are enabled.
func TestAnalyze_GraphsEnabled_PopulatesTaintPathForChain(t *testing.T) {
	sourceAssign := &ir.IRNode{
		NodeID: "a1",
		Kind:   ir.NodeKindAssignment,
		Attrs:  map[string]any{"lhs": "user_id", "rhs": "request.args.get('id')"},
		Children: []*ir.IRNode{
			{Kind: ir.NodeKindIdentifier, Text: "user_id"},
			{Kind: ir.NodeKindIdentifier, Text: "_"},
		},
	}
	propagateAssign := &ir.IRNode{
		NodeID: "a2",
		Kind:   ir.NodeKindAssignment,
		Attrs:  map[string]any{"lhs": "query", "rhs": "\"SELECT \" + user_id"},
		Children: []*ir.IRNode{
			{Kind: ir.NodeKindIdentifier, Text: "query"},
			{Kind: ir.NodeKindIdentifier, Text: "user_id"},
		},
	}
	root := &ir.IRNode{Kind: ir.NodeKindModule, Children: []*ir.IRNode{sourceAssign, propagateAssign}}

	result, err := analyzer.New(true).Analyze(context.Background(), pythonFile(root))
	if err != nil {
		t.Fatalf("Analyze returned error: %v", err)
	}
	if !result.TaintedVars["query"] {
		t.Fatal("expected query to be tainted")
	}
	path := result.TaintPaths["query"]
	if len(path) != 2 {
		t.Fatalf("expected a 2-hop path (source assignment + propagation), got %d: %v", len(path), path)
	}
}
