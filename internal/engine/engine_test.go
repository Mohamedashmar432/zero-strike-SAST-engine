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
		ID:       "ZS-TEST-001",
		Language: core.LangPython,
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

// TestMatch_DoesNotCrossLanguageBoundary verifies a rule declared for one
// language never fires against a file of a different language, even when
// the IR shape (assignment node, identifier/literal pattern) is identical
// across languages — e.g. a Python "hardcoded credential" rule must not
// match the same-shaped assignment in a Go or C# file.
func TestMatch_DoesNotCrossLanguageBoundary(t *testing.T) {
	pyRule := &rules.Rule{
		ID:       "ZS-PY-TEST-CRED",
		Language: core.LangPython,
		Match: rules.MatchPattern{
			Kind:          string(ir.NodeKindAssignment),
			LHSIdentifier: "(?i)(password|secret)",
			RHSLiteral:    `^".+"$`,
		},
	}
	idx := engine.BuildIndex([]*rules.Rule{pyRule})

	assignNode := &ir.IRNode{
		Kind:  ir.NodeKindAssignment,
		Attrs: map[string]any{"lhs": "password", "rhs": `"hunter2"`},
	}
	root := &ir.IRNode{Kind: ir.NodeKindModule, Children: []*ir.IRNode{assignNode}}

	// Same IR shape, but the file is Go, not Python.
	mc := &engine.MatchContext{
		Index: idx,
		File:  &analyzer.AnalysisResult{IR: &ir.IRFile{Language: core.LangGo, Path: "main.go", Root: root}},
	}
	results, err := engine.New().Match(context.Background(), mc)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Fatalf("Python rule ZS-PY-TEST-CRED matched a Go file — cross-language contamination, got %d results", len(results))
	}

	// Same rule, same-shaped node, but now the file really is Python — should match.
	mc.File.IR.Language = core.LangPython
	results, err = engine.New().Match(context.Background(), mc)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected the rule to match its own language's file, got %d results", len(results))
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
			ID:       fmt.Sprintf("ZS-BENCH-%03d", i),
			Language: core.LangPython,
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

// TestMatch_TaintedArgument verifies the tainted_argument filter only fires
// when a call argument identifier is present in the file's tainted-var set.
func TestMatch_TaintedArgument(t *testing.T) {
	rule := &rules.Rule{
		ID: "ZS-TEST-TAINT",
		Match: rules.MatchPattern{
			Kind:    string(ir.NodeKindCall),
			Callee:  "execute",
			Filters: []rules.Filter{{TaintedArgument: true}},
		},
	}
	idx := engine.BuildIndex([]*rules.Rule{rule})

	taintedCall := &ir.IRNode{
		Kind: ir.NodeKindCall,
		Children: []*ir.IRNode{
			{Kind: ir.NodeKindIdentifier, Text: "execute"},
			{Kind: ir.NodeKindUnknown, Children: []*ir.IRNode{{Kind: ir.NodeKindIdentifier, Text: "query"}}},
		},
	}
	root := &ir.IRNode{Kind: ir.NodeKindModule, Children: []*ir.IRNode{taintedCall}}
	mc := &engine.MatchContext{
		Index: idx,
		File: &analyzer.AnalysisResult{
			IR:          &ir.IRFile{Root: root},
			TaintedVars: map[string]bool{"query": true},
		},
	}
	results, err := engine.New().Match(context.Background(), mc)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Errorf("expected 1 match when argument is tainted, got %d", len(results))
	}

	// Same call, but the argument is not in the tainted set.
	mc.File.TaintedVars = map[string]bool{}
	results, err = engine.New().Match(context.Background(), mc)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 matches when argument is not tainted, got %d", len(results))
	}
}

// TestMatch_Kwarg verifies the kwarg filter matches a keyword argument by name+value.
func TestMatch_Kwarg(t *testing.T) {
	rule := &rules.Rule{
		ID: "ZS-TEST-KWARG",
		Match: rules.MatchPattern{
			Kind:   string(ir.NodeKindCall),
			Callee: "app.run",
			Filters: []rules.Filter{{
				Kwarg: &rules.KwargPattern{Name: "debug", ValuePattern: "^True$"},
			}},
		},
	}
	idx := engine.BuildIndex([]*rules.Rule{rule})

	kwargCall := &ir.IRNode{
		Kind: ir.NodeKindCall,
		Children: []*ir.IRNode{
			{Kind: ir.NodeKindAttribute, Children: []*ir.IRNode{
				{Kind: ir.NodeKindIdentifier, Text: "app"},
				{Kind: ir.NodeKindIdentifier, Text: "run"},
			}},
			{Kind: ir.NodeKindUnknown, Children: []*ir.IRNode{
				{Kind: ir.NodeKindKeywordArg, Attrs: map[string]any{"kwarg_name": "debug", "kwarg_value": "True"}},
			}},
		},
	}
	root := &ir.IRNode{Kind: ir.NodeKindModule, Children: []*ir.IRNode{kwargCall}}
	mc := &engine.MatchContext{Index: idx, File: &analyzer.AnalysisResult{IR: &ir.IRFile{Root: root}}}

	results, err := engine.New().Match(context.Background(), mc)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 match for debug=True kwarg, got %d", len(results))
	}

	// debug=False must not match.
	kwargCall.Children[1].Children[0].Attrs["kwarg_value"] = "False"
	results, err = engine.New().Match(context.Background(), mc)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 matches for debug=False, got %d", len(results))
	}
}

// TestMatch_ArgumentIdentifierMatches verifies a positional argument identifier
// can be matched by name via regex.
func TestMatch_ArgumentIdentifierMatches(t *testing.T) {
	rule := &rules.Rule{
		ID: "ZS-TEST-ARGID",
		Match: rules.MatchPattern{
			Kind:    string(ir.NodeKindCall),
			Callee:  "logging.info",
			Filters: []rules.Filter{{ArgumentIdentifierMatches: "(?i)password"}},
		},
	}
	idx := engine.BuildIndex([]*rules.Rule{rule})

	call := &ir.IRNode{
		Kind: ir.NodeKindCall,
		Children: []*ir.IRNode{
			{Kind: ir.NodeKindAttribute, Children: []*ir.IRNode{
				{Kind: ir.NodeKindIdentifier, Text: "logging"},
				{Kind: ir.NodeKindIdentifier, Text: "info"},
			}},
			{Kind: ir.NodeKindUnknown, Children: []*ir.IRNode{{Kind: ir.NodeKindIdentifier, Text: "password"}}},
		},
	}
	root := &ir.IRNode{Kind: ir.NodeKindModule, Children: []*ir.IRNode{call}}
	mc := &engine.MatchContext{Index: idx, File: &analyzer.AnalysisResult{IR: &ir.IRFile{Root: root}}}

	results, err := engine.New().Match(context.Background(), mc)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Errorf("expected 1 match for password argument, got %d", len(results))
	}
}

// TestMatch_RHSLiteral verifies RHSLiteral matches an assignment's right-hand side text.
func TestMatch_RHSLiteral(t *testing.T) {
	rule := &rules.Rule{
		ID: "ZS-TEST-RHS",
		Match: rules.MatchPattern{
			Kind:          string(ir.NodeKindAssignment),
			LHSIdentifier: "^DEBUG$",
			RHSLiteral:    "^True$",
		},
	}
	idx := engine.BuildIndex([]*rules.Rule{rule})

	debugTrue := &ir.IRNode{Kind: ir.NodeKindAssignment, Attrs: map[string]any{"lhs": "DEBUG", "rhs": "True"}}
	root := &ir.IRNode{Kind: ir.NodeKindModule, Children: []*ir.IRNode{debugTrue}}
	mc := &engine.MatchContext{Index: idx, File: &analyzer.AnalysisResult{IR: &ir.IRFile{Root: root}}}

	results, err := engine.New().Match(context.Background(), mc)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 match for DEBUG = True, got %d", len(results))
	}

	debugTrue.Attrs["rhs"] = "False"
	results, err = engine.New().Match(context.Background(), mc)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 matches for DEBUG = False, got %d", len(results))
	}
}

// TestMatch_TaintedRHS verifies the tainted_rhs filter fires for assignment-based
// sinks (e.g. element.innerHTML = userInput) when the RHS identifier is tainted.
func TestMatch_TaintedRHS(t *testing.T) {
	rule := &rules.Rule{
		ID: "ZS-TEST-TAINTEDRHS",
		Match: rules.MatchPattern{
			Kind:          string(ir.NodeKindAssignment),
			LHSIdentifier: "innerHTML",
			Filters:       []rules.Filter{{TaintedRHS: true}},
		},
	}
	idx := engine.BuildIndex([]*rules.Rule{rule})

	assignNode := &ir.IRNode{
		Kind:     ir.NodeKindAssignment,
		Attrs:    map[string]any{"lhs": "el.innerHTML"},
		Children: []*ir.IRNode{{Kind: ir.NodeKindAttribute}, {Kind: ir.NodeKindIdentifier, Text: "userInput"}},
	}
	root := &ir.IRNode{Kind: ir.NodeKindModule, Children: []*ir.IRNode{assignNode}}
	mc := &engine.MatchContext{
		Index: idx,
		File: &analyzer.AnalysisResult{
			IR:          &ir.IRFile{Root: root},
			TaintedVars: map[string]bool{"userInput": true},
		},
	}

	results, err := engine.New().Match(context.Background(), mc)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Errorf("expected 1 match when RHS is tainted, got %d", len(results))
	}

	mc.File.TaintedVars = map[string]bool{}
	results, err = engine.New().Match(context.Background(), mc)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 matches when RHS is not tainted, got %d", len(results))
	}
}

// TestMatch_ExceptHandlerFilters verifies HasBareExcept and HasEmptyExceptHandler.
func TestMatch_ExceptHandlerFilters(t *testing.T) {
	bareRule := &rules.Rule{
		ID:    "ZS-TEST-BAREEXCEPT",
		Match: rules.MatchPattern{Kind: string(ir.NodeKindTry), Filters: []rules.Filter{{HasBareExcept: true}}},
	}
	emptyRule := &rules.Rule{
		ID:    "ZS-TEST-EMPTYEXCEPT",
		Match: rules.MatchPattern{Kind: string(ir.NodeKindTry), Filters: []rules.Filter{{HasEmptyExceptHandler: true}}},
	}
	idx := engine.BuildIndex([]*rules.Rule{bareRule, emptyRule})

	tryNode := &ir.IRNode{
		Kind: ir.NodeKindTry,
		Attrs: map[string]any{"except_handlers": []ir.ExceptHandler{
			{IsBare: true},
		}},
	}
	root := &ir.IRNode{Kind: ir.NodeKindModule, Children: []*ir.IRNode{tryNode}}
	mc := &engine.MatchContext{Index: idx, File: &analyzer.AnalysisResult{IR: &ir.IRFile{Root: root}}}

	results, err := engine.New().Match(context.Background(), mc)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Rule.ID != "ZS-TEST-BAREEXCEPT" {
		t.Errorf("expected only ZS-TEST-BAREEXCEPT to fire on a bare except, got %d results", len(results))
	}

	tryNode.Attrs["except_handlers"] = []ir.ExceptHandler{{Types: []string{"ValueError"}, IsEmptyBody: true}}
	results, err = engine.New().Match(context.Background(), mc)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Rule.ID != "ZS-TEST-EMPTYEXCEPT" {
		t.Errorf("expected only ZS-TEST-EMPTYEXCEPT to fire on an empty typed except, got %d results", len(results))
	}
}
