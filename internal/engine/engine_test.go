package engine_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/zerostrike/scanner/internal/analyzer"
	"github.com/zerostrike/scanner/internal/core"
	"github.com/zerostrike/scanner/internal/engine"
	"github.com/zerostrike/scanner/internal/ir"
	"github.com/zerostrike/scanner/internal/rules"
)

// TestMatch_BasicCall verifies that a call rule matches the correct node.
func TestMatch_BasicCall(t *testing.T) {
	callNode := &ir.IRNode{
		Kind: ir.NodeKindCall,
		Children: []*ir.IRNode{
			{Kind: ir.NodeKindIdentifier, Text: "eval"},
		},
		Attrs: map[string]any{"argument_count": 1},
	}
	root := &ir.IRNode{Kind: ir.NodeKindModule, Children: []*ir.IRNode{callNode}}

	rule := &rules.Rule{
		ID: "ZS-TEST-001",
		Match: rules.MatchPattern{
			Kind:   string(ir.NodeKindCall),
			Callee: "eval",
		},
		Severity:   core.SeverityHigh,
		Confidence: core.ConfidenceHigh,
	}

	idx := engine.BuildIndex([]*rules.Rule{rule})
	mc := &engine.MatchContext{
		Index: idx,
		File: &analyzer.AnalysisResult{
			IR: &ir.IRFile{Language: core.LangPython, Path: "test.py", Root: root},
		},
	}

	results, err := engine.New().Match(context.Background(), mc)
	if err != nil {
		t.Fatalf("Match error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 match, got %d", len(results))
	}
	if results[0].Rule.ID != "ZS-TEST-001" {
		t.Errorf("wrong rule matched: %s", results[0].Rule.ID)
	}
}

// TestMatch_NilIndex returns empty results without panic.
func TestMatch_NilIndex(t *testing.T) {
	mc := &engine.MatchContext{
		Index: nil,
		File: &analyzer.AnalysisResult{
			IR: &ir.IRFile{Root: &ir.IRNode{Kind: ir.NodeKindModule}},
		},
	}
	results, err := engine.New().Match(context.Background(), mc)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results with nil index, got %d", len(results))
	}
}

// TestBuildIndex_200Rules verifies that matching 200 rules against a 10-node IR
// scales with node count, not rules×nodes. The result count must be correct.
func TestBuildIndex_200Rules(t *testing.T) {
	const numRules = 200
	ruleList := make([]*rules.Rule, numRules)
	for i := range ruleList {
		ruleList[i] = &rules.Rule{
			ID: fmt.Sprintf("ZS-BENCH-%03d", i),
			Match: rules.MatchPattern{
				Kind:   string(ir.NodeKindCall),
				Callee: fmt.Sprintf("func_%d", i),
			},
			Severity:   core.SeverityLow,
			Confidence: core.ConfidenceLow,
		}
	}
	// Rule 0 matches "func_0" — add a call to "func_0" in the IR.
	callNode := &ir.IRNode{
		Kind: ir.NodeKindCall,
		Children: []*ir.IRNode{
			{Kind: ir.NodeKindIdentifier, Text: "func_0"},
		},
	}
	root := &ir.IRNode{Kind: ir.NodeKindModule, Children: []*ir.IRNode{callNode}}
	// Add 8 more non-matching call nodes.
	for i := 1; i <= 8; i++ {
		root.Children = append(root.Children, &ir.IRNode{
			Kind:     ir.NodeKindCall,
			Children: []*ir.IRNode{{Kind: ir.NodeKindIdentifier, Text: fmt.Sprintf("other_%d", i)}},
		})
	}
	// One non-call node.
	root.Children = append(root.Children, &ir.IRNode{Kind: ir.NodeKindAssignment})

	idx := engine.BuildIndex(ruleList)
	mc := &engine.MatchContext{
		Index: idx,
		File: &analyzer.AnalysisResult{
			IR: &ir.IRFile{Language: core.LangPython, Path: "bench.py", Root: root},
		},
	}

	results, err := engine.New().Match(context.Background(), mc)
	if err != nil {
		t.Fatalf("Match error: %v", err)
	}
	// Only rule 0 matches (func_0 call).
	if len(results) != 1 {
		t.Errorf("expected exactly 1 match from 200 rules, got %d", len(results))
	}
}

// TestMatch_NoCalleeRule verifies a call rule without callee matches any call node.
func TestMatch_NoCalleeRule(t *testing.T) {
	// ponytail: no-callee call rules are deliberately disallowed by the validator (C9),
	// but BuildIndex accepts them and puts them in byKind for general call matching.
	anyCallRule := &rules.Rule{
		ID:         "ZS-TEST-ANY",
		Match:      rules.MatchPattern{Kind: string(ir.NodeKindCall)},
		Severity:   core.SeverityInfo,
		Confidence: core.ConfidenceLow,
	}
	callNode := &ir.IRNode{
		Kind:     ir.NodeKindCall,
		Children: []*ir.IRNode{{Kind: ir.NodeKindIdentifier, Text: "anything"}},
	}
	root := &ir.IRNode{Kind: ir.NodeKindModule, Children: []*ir.IRNode{callNode}}

	idx := engine.BuildIndex([]*rules.Rule{anyCallRule})
	mc := &engine.MatchContext{
		Index: idx,
		File:  &analyzer.AnalysisResult{IR: &ir.IRFile{Root: root}},
	}

	results, err := engine.New().Match(context.Background(), mc)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Errorf("expected 1 match for no-callee call rule, got %d", len(results))
	}
}
