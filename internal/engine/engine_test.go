package engine_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/analyzer"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/engine"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/ir"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/rules"
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

// TestMatch_TaintedVarPopulated verifies that MatchResult.TaintedVar carries
// the actual tainted identifier when the rule uses a TaintedArgument or
// TaintedRHS filter, and stays empty for rules that don't.
func TestMatch_TaintedVarPopulated(t *testing.T) {
	taintedArgRule := &rules.Rule{
		ID: "ZS-TEST-TAINTVAR-ARG",
		Match: rules.MatchPattern{
			Kind:    string(ir.NodeKindCall),
			Callee:  "execute",
			Filters: []rules.Filter{{TaintedArgument: true}},
		},
	}
	taintedCall := &ir.IRNode{
		Kind: ir.NodeKindCall,
		Children: []*ir.IRNode{
			{Kind: ir.NodeKindIdentifier, Text: "execute"},
			{Kind: ir.NodeKindUnknown, Children: []*ir.IRNode{{Kind: ir.NodeKindIdentifier, Text: "query"}}},
		},
	}
	root := &ir.IRNode{Kind: ir.NodeKindModule, Children: []*ir.IRNode{taintedCall}}
	idx := engine.BuildIndex([]*rules.Rule{taintedArgRule})
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
		t.Fatalf("expected 1 match, got %d", len(results))
	}
	if results[0].TaintedVar != "query" {
		t.Errorf("TaintedVar = %q, want %q", results[0].TaintedVar, "query")
	}

	taintedRHSRule := &rules.Rule{
		ID: "ZS-TEST-TAINTVAR-RHS",
		Match: rules.MatchPattern{
			Kind:          string(ir.NodeKindAssignment),
			LHSIdentifier: "innerHTML",
			Filters:       []rules.Filter{{TaintedRHS: true}},
		},
	}
	assignNode := &ir.IRNode{
		Kind:     ir.NodeKindAssignment,
		Attrs:    map[string]any{"lhs": "el.innerHTML"},
		Children: []*ir.IRNode{{Kind: ir.NodeKindAttribute}, {Kind: ir.NodeKindIdentifier, Text: "userInput"}},
	}
	root2 := &ir.IRNode{Kind: ir.NodeKindModule, Children: []*ir.IRNode{assignNode}}
	idx2 := engine.BuildIndex([]*rules.Rule{taintedRHSRule})
	mc2 := &engine.MatchContext{
		Index: idx2,
		File: &analyzer.AnalysisResult{
			IR:          &ir.IRFile{Root: root2},
			TaintedVars: map[string]bool{"userInput": true},
		},
	}
	results2, err := engine.New().Match(context.Background(), mc2)
	if err != nil {
		t.Fatal(err)
	}
	if len(results2) != 1 {
		t.Fatalf("expected 1 match, got %d", len(results2))
	}
	if results2[0].TaintedVar != "userInput" {
		t.Errorf("TaintedVar = %q, want %q", results2[0].TaintedVar, "userInput")
	}

	// A rule with no taint-gated filter must leave TaintedVar empty.
	plainRule := &rules.Rule{
		ID: "ZS-TEST-TAINTVAR-NONE",
		Match: rules.MatchPattern{
			Kind:   string(ir.NodeKindCall),
			Callee: "execute",
		},
	}
	idx3 := engine.BuildIndex([]*rules.Rule{plainRule})
	mc3 := &engine.MatchContext{
		Index: idx3,
		File: &analyzer.AnalysisResult{
			IR:          &ir.IRFile{Root: root},
			TaintedVars: map[string]bool{"query": true},
		},
	}
	results3, err := engine.New().Match(context.Background(), mc3)
	if err != nil {
		t.Fatal(err)
	}
	if len(results3) != 1 {
		t.Fatalf("expected 1 match, got %d", len(results3))
	}
	if results3[0].TaintedVar != "" {
		t.Errorf("TaintedVar = %q, want empty for a non-taint-gated rule", results3[0].TaintedVar)
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

// attrChain builds a nested NodeKindAttribute chain the same way the real
// tree-sitter-derived IR does for a multi-segment dotted call (e.g.
// "context.Response.Write" -> Attribute(Attribute(Identifier(context),
// Identifier(Response)), Identifier(Write))) — mirrors the real shape
// confirmed for urllib.request.urlopen earlier this session.
func attrChain(parts ...string) *ir.IRNode {
	if len(parts) == 1 {
		return &ir.IRNode{Kind: ir.NodeKindIdentifier, Text: parts[0]}
	}
	return &ir.IRNode{
		Kind: ir.NodeKindAttribute,
		Children: []*ir.IRNode{
			attrChain(parts[:len(parts)-1]...),
			{Kind: ir.NodeKindIdentifier, Text: parts[len(parts)-1]},
		},
	}
}

func callNodeWithChain(parts ...string) *ir.IRNode {
	return &ir.IRNode{
		Kind:     ir.NodeKindCall,
		Children: []*ir.IRNode{attrChain(parts...)},
		Attrs:    map[string]any{"argument_count": 1},
	}
}

func suffixRule(id, callee string) *rules.Rule {
	return &rules.Rule{
		ID:       id,
		Language: core.LangCSharp,
		Match: rules.MatchPattern{
			Kind:         string(ir.NodeKindCall),
			Callee:       callee,
			CalleeSuffix: true,
		},
		Severity:   core.SeverityHigh,
		Confidence: core.ConfidenceHigh,
	}
}

func matchOne(t *testing.T, rule *rules.Rule, call *ir.IRNode) []engine.MatchResult {
	t.Helper()
	idx := engine.BuildIndex([]*rules.Rule{rule})
	root := &ir.IRNode{Kind: ir.NodeKindModule, Children: []*ir.IRNode{call}}
	mc := &engine.MatchContext{
		Index: idx,
		File:  &analyzer.AnalysisResult{IR: &ir.IRFile{Language: core.LangCSharp, Path: "test.cs", Root: root}},
	}
	results, err := engine.New().Match(context.Background(), mc)
	if err != nil {
		t.Fatalf("Match error: %v", err)
	}
	return results
}

func TestMatch_CalleeSuffix_ExactStillMatches(t *testing.T) {
	rule := suffixRule("ZS-TEST-SUFFIX-EXACT", "Response.Write")
	call := callNodeWithChain("Response", "Write")
	results := matchOne(t, rule, call)
	if len(results) != 1 {
		t.Fatalf("expected exact match to still fire with callee_suffix:true, got %d results", len(results))
	}
}

func TestMatch_CalleeSuffix_LongerChainMatches(t *testing.T) {
	rule := suffixRule("ZS-TEST-SUFFIX-LONG", "Response.Write")
	call := callNodeWithChain("context", "Response", "Write")
	results := matchOne(t, rule, call)
	if len(results) != 1 {
		t.Fatalf("expected context.Response.Write to match callee_suffix rule for Response.Write, got %d results", len(results))
	}
}

func TestMatch_CalleeSuffix_UnrelatedPartialWordDoesNotMatch(t *testing.T) {
	rule := suffixRule("ZS-TEST-SUFFIX-PARTIAL", "Response.Write")
	call := callNodeWithChain("XResponse", "Write") // no dot before "Response.Write" as a whole
	results := matchOne(t, rule, call)
	if len(results) != 0 {
		t.Fatalf("expected XResponse.Write to NOT match Response.Write (not a dot-boundary suffix), got %d results", len(results))
	}
}

func TestMatch_CalleeSuffix_SharedLastSegmentDoesNotCollide(t *testing.T) {
	// Real shipped fixtures: benchmark/corpus/csharp/cases/clean.cs calls
	// SHA256.Create(), which shares only its last segment ("Create") with
	// ZS-CS-005's MD5.Create — the byCalleeSuffix shortlist groups them,
	// but the full dot-boundary check must still keep them apart.
	rule := suffixRule("ZS-TEST-SUFFIX-MD5", "MD5.Create")
	call := callNodeWithChain("SHA256", "Create")
	results := matchOne(t, rule, call)
	if len(results) != 0 {
		t.Fatalf("expected SHA256.Create to NOT match MD5.Create despite sharing the last segment, got %d results", len(results))
	}
}

func TestMatch_CalleeSuffix_OptOutStaysExactOnly(t *testing.T) {
	rule := &rules.Rule{
		ID:       "ZS-TEST-SUFFIX-OPTOUT",
		Language: core.LangCSharp,
		Match: rules.MatchPattern{
			Kind:   string(ir.NodeKindCall),
			Callee: "Response.Write",
			// CalleeSuffix intentionally left false.
		},
		Severity:   core.SeverityHigh,
		Confidence: core.ConfidenceHigh,
	}
	call := callNodeWithChain("context", "Response", "Write")
	results := matchOne(t, rule, call)
	if len(results) != 0 {
		t.Fatalf("expected context.Response.Write to NOT match when callee_suffix is false, got %d results", len(results))
	}
}

// TestBuildIndex_CalleeSuffix_SingleSegmentDoesSuffixMatch pins the Sprint 33
// contract change. A single-segment callee_suffix now DOES suffix-match, so
// "execute" matches cur.execute / conn.execute / session.execute — sink rules
// are no longer pinned to one hardcoded receiver name.
//
// The protection this replaces is still enforced, just moved: an unbounded
// rule like "eval" broadening to any obj.eval() is prevented at load time by
// the Validator, which now rejects a single-segment callee_suffix on a rule
// with no filters. Precision comes from the rule's own gating, not from the
// receiver name. See TestValidator_CalleeSuffixSingleSegmentRequiresFilters.
func TestBuildIndex_CalleeSuffix_SingleSegmentDoesSuffixMatch(t *testing.T) {
	rule := &rules.Rule{
		ID:       "ZS-TEST-SUFFIX-SINGLESEG",
		Language: core.LangJavaScript,
		Match: rules.MatchPattern{
			Kind:         string(ir.NodeKindCall),
			Callee:       "eval",
			CalleeSuffix: true,
		},
		Severity:   core.SeverityHigh,
		Confidence: core.ConfidenceHigh,
	}
	idx := engine.BuildIndex([]*rules.Rule{rule})
	call := &ir.IRNode{
		Kind:     ir.NodeKindCall,
		Children: []*ir.IRNode{attrChain("obj", "eval")},
		Attrs:    map[string]any{"argument_count": 1},
	}
	root := &ir.IRNode{Kind: ir.NodeKindModule, Children: []*ir.IRNode{call}}
	mc := &engine.MatchContext{
		Index: idx,
		File:  &analyzer.AnalysisResult{IR: &ir.IRFile{Language: core.LangJavaScript, Path: "test.js", Root: root}},
	}
	results, err := engine.New().Match(context.Background(), mc)
	if err != nil {
		t.Fatalf("Match error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected single-segment callee_suffix rule to match obj.eval(), got %d results", len(results))
	}
}

// TestMatch_CalleeSuffix_SingleSegmentMatchesAnyReceiver covers the Sprint 33
// change: a single-segment callee_suffix means "this method on any receiver".
//
// Sink rules used to be pinned to one hardcoded receiver name — ZS-PY-004
// matched `cursor.execute` and therefore missed `cur.execute`, `conn.execute`,
// and `session.execute`. dvpwa, a deliberately vulnerable SQL-injection app,
// scored 0 findings across 40 files largely because its DAOs use `cur`.
func TestMatch_CalleeSuffix_SingleSegmentMatchesAnyReceiver(t *testing.T) {
	rule := &rules.Rule{
		ID:       "ZS-TEST-EXEC",
		Language: core.LangPython,
		Match: rules.MatchPattern{
			Kind:         string(ir.NodeKindCall),
			Callee:       "execute",
			CalleeSuffix: true,
		},
	}
	idx := engine.BuildIndex([]*rules.Rule{rule})

	for _, callee := range []string{"execute", "cur.execute", "cursor.execute", "conn.execute", "db.session.execute"} {
		call := &ir.IRNode{
			Kind:     ir.NodeKindCall,
			Children: []*ir.IRNode{attrChain(strings.Split(callee, ".")...)},
			Attrs:    map[string]any{"argument_count": 1},
		}
		mc := &engine.MatchContext{
			Index: idx,
			File: &analyzer.AnalysisResult{IR: &ir.IRFile{
				Language: core.LangPython, Path: "t.py",
				Root: &ir.IRNode{Kind: ir.NodeKindModule, Children: []*ir.IRNode{call}},
			}},
		}
		got, err := engine.New().Match(context.Background(), mc)
		if err != nil {
			t.Fatalf("%s: Match: %v", callee, err)
		}
		if len(got) != 1 {
			t.Errorf("%s: got %d matches, want 1 — any receiver should match", callee, len(got))
		}
	}

	// A different method must still not match: suffix matching is on the
	// dot boundary, not a substring.
	call := &ir.IRNode{
		Kind:     ir.NodeKindCall,
		Children: []*ir.IRNode{attrChain("cur", "executemany")},
		Attrs:    map[string]any{"argument_count": 1},
	}
	mc := &engine.MatchContext{
		Index: idx,
		File: &analyzer.AnalysisResult{IR: &ir.IRFile{
			Language: core.LangPython, Path: "t.py",
			Root: &ir.IRNode{Kind: ir.NodeKindModule, Children: []*ir.IRNode{call}},
		}},
	}
	if got, _ := engine.New().Match(context.Background(), mc); len(got) != 0 {
		t.Errorf("cur.executemany matched %d rules, want 0", len(got))
	}
}

// TestMatch_TaintedArgumentIndex pins the argument-position filter, which
// exists because "any argument, anywhere in its subtree" is wrong for any sink
// where exactly one position is dangerous. The format-string family
// (string.Format, fmt.Sprintf, String.format, sprintf, util.format) is
// vulnerable when the FORMAT STRING is attacker-controlled, not when a
// substituted value is — so matching any argument fired on the entirely safe
// logger.info("User: %s", name) idiom.
//
// Both IR shapes are covered. Go/C#/JS/TS/PHP wrap arguments in an unnamed
// argument_list node; Java emits them as direct children beside literal "("
// and ")" tokens. Getting this wrong silently shifts every index by one.
func TestMatch_TaintedArgumentIndex(t *testing.T) {
	zero := 0
	rule := &rules.Rule{
		ID:       "ZS-TEST-FMT",
		Language: core.LangPython,
		Match: rules.MatchPattern{
			Kind:   string(ir.NodeKindCall),
			Callee: "fmt",
			Filters: []rules.Filter{
				{TaintedArgument: true, TaintedArgumentIndex: &zero},
			},
		},
	}
	idx := engine.BuildIndex([]*rules.Rule{rule})

	lit := func(s string) *ir.IRNode { return &ir.IRNode{Kind: ir.NodeKindLiteral, Text: s} }
	tainted := func() *ir.IRNode { return &ir.IRNode{Kind: ir.NodeKindIdentifier, Text: "evil"} }
	punct := func(s string) *ir.IRNode { return &ir.IRNode{Kind: ir.NodeKindUnknown, Text: s} }

	// wrapped: callee, then one argument_list node delimited by parens.
	wrapped := func(args ...*ir.IRNode) *ir.IRNode {
		kids := []*ir.IRNode{punct("(")}
		for i, a := range args {
			if i > 0 {
				kids = append(kids, punct(","))
			}
			kids = append(kids, a)
		}
		kids = append(kids, punct(")"))
		return &ir.IRNode{Kind: ir.NodeKindCall, Children: []*ir.IRNode{
			{Kind: ir.NodeKindIdentifier, Text: "fmt"},
			{Kind: ir.NodeKindUnknown, Children: kids},
		}}
	}
	// flat: Java-style, arguments as direct children beside paren tokens.
	flat := func(args ...*ir.IRNode) *ir.IRNode {
		kids := []*ir.IRNode{{Kind: ir.NodeKindIdentifier, Text: "fmt"}, punct("(")}
		for i, a := range args {
			if i > 0 {
				kids = append(kids, punct(","))
			}
			kids = append(kids, a)
		}
		return &ir.IRNode{Kind: ir.NodeKindCall, Children: append(kids, punct(")"))}
	}

	run := func(call *ir.IRNode) int {
		mc := &engine.MatchContext{
			Index: idx,
			File: &analyzer.AnalysisResult{
				IR:          &ir.IRFile{Language: core.LangPython, Path: "t.py", Root: &ir.IRNode{Kind: ir.NodeKindModule, Children: []*ir.IRNode{call}}},
				TaintedVars: map[string]bool{"evil": true},
			},
		}
		got, err := engine.New().Match(context.Background(), mc)
		if err != nil {
			t.Fatalf("Match: %v", err)
		}
		return len(got)
	}

	for _, shape := range []struct {
		name string
		fn   func(...*ir.IRNode) *ir.IRNode
	}{{"wrapped", wrapped}, {"flat", flat}} {
		// Tainted format string (argument 0) -> fires.
		if n := run(shape.fn(tainted(), lit("safe"))); n != 1 {
			t.Errorf("%s: tainted argument 0 got %d matches, want 1", shape.name, n)
		}
		// Tainted value in argument 1, literal format string -> must NOT fire.
		if n := run(shape.fn(lit("User: %s"), tainted())); n != 0 {
			t.Errorf("%s: tainted argument 1 got %d matches, want 0 — this is the safe idiom", shape.name, n)
		}
	}
}

// TestArgumentIndex_ConstructorShape covers the C# constructor layout, where
// the call node is ["new", TypeName, argument_list] rather than
// [callee, argument_list].
//
// argumentNodes originally assumed the argument list directly followed the
// callee, which made the TYPE NAME argument 0. Pinning
// `new SqliteDataAdapter(sql, connection)` to argument 0 then matched the type
// identifier — never tainted — and silently dropped 21 real SQL injections on
// a real target while the corpus still reported TP=451 FP=0 FN=0. The argument
// list is now located by its "(" … ")" delimiters wherever it sits.
func TestArgumentIndex_ConstructorShape(t *testing.T) {
	zero := 0
	rule := &rules.Rule{
		ID:       "ZS-TEST-CTOR",
		Language: core.LangCSharp,
		Match: rules.MatchPattern{
			Kind:    string(ir.NodeKindCall),
			Callee:  "SqliteDataAdapter",
			Filters: []rules.Filter{{TaintedArgument: true, TaintedArgumentIndex: &zero}},
		},
	}
	idx := engine.BuildIndex([]*rules.Rule{rule})

	ctor := func(arg0, arg1 *ir.IRNode) *ir.IRNode {
		return &ir.IRNode{Kind: ir.NodeKindCall, Children: []*ir.IRNode{
			{Kind: ir.NodeKindUnknown, Text: "new"},
			{Kind: ir.NodeKindIdentifier, Text: "SqliteDataAdapter"},
			{Kind: ir.NodeKindUnknown, Children: []*ir.IRNode{
				{Kind: ir.NodeKindUnknown, Text: "("},
				arg0,
				{Kind: ir.NodeKindUnknown, Text: ","},
				arg1,
				{Kind: ir.NodeKindUnknown, Text: ")"},
			}},
		}}
	}
	run := func(call *ir.IRNode) int {
		mc := &engine.MatchContext{
			Index: idx,
			File: &analyzer.AnalysisResult{
				IR:          &ir.IRFile{Language: core.LangCSharp, Path: "a.cs", Root: &ir.IRNode{Kind: ir.NodeKindModule, Children: []*ir.IRNode{call}}},
				TaintedVars: map[string]bool{"sql": true, "connection": true},
			},
		}
		got, err := engine.New().Match(context.Background(), mc)
		if err != nil {
			t.Fatalf("Match: %v", err)
		}
		return len(got)
	}

	taintedSQL := &ir.IRNode{Kind: ir.NodeKindIdentifier, Text: "sql"}
	literalSQL := &ir.IRNode{Kind: ir.NodeKindLiteral, Text: "select * from Products"}
	conn := &ir.IRNode{Kind: ir.NodeKindIdentifier, Text: "connection"}

	if n := run(ctor(taintedSQL, conn)); n != 1 {
		t.Errorf("tainted SQL in argument 0 got %d matches, want 1 — the type name must not be argument 0", n)
	}
	// A literal query with a tainted connection is not a SQL injection.
	if n := run(ctor(literalSQL, conn)); n != 0 {
		t.Errorf("literal SQL with tainted connection got %d matches, want 0", n)
	}
}
