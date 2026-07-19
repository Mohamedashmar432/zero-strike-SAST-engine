package engine_test

import (
	"context"
	"testing"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/analyzer"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/engine"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/ir"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/rules"
)

// htmlElement builds the IR shape the HTML builder produces for one element:
// a call node whose first child is the tag-name identifier and whose remaining
// children are keyword_argument nodes (one per attribute). This lets the engine
// filter logic (kwarg / kwarg_name_matches / not) be tested without cgo/tree-sitter.
func htmlElement(tag string, attrs [][2]string) *ir.IRNode {
	children := []*ir.IRNode{{Kind: ir.NodeKindIdentifier, Text: tag}}
	for _, kv := range attrs {
		children = append(children, &ir.IRNode{
			Kind:  ir.NodeKindKeywordArg,
			Attrs: map[string]any{"kwarg_name": kv[0], "kwarg_value": kv[1]},
		})
	}
	return &ir.IRNode{Kind: ir.NodeKindCall, Children: children, Attrs: map[string]any{}}
}

func matchHTML(t *testing.T, rule *rules.Rule, elements ...*ir.IRNode) int {
	t.Helper()
	root := &ir.IRNode{Kind: ir.NodeKindModule, Children: elements}
	mc := &engine.MatchContext{
		Index: engine.BuildIndex([]*rules.Rule{rule}),
		File: &analyzer.AnalysisResult{
			IR: &ir.IRFile{Language: core.LangHTML, Path: "t.html", Root: root},
		},
	}
	res, err := engine.New().Match(context.Background(), mc)
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	return len(res)
}

// TestHTML_KwargNameMatches verifies the on* inline-handler rule shape
// (ZS-HTML-003): a callee-less, filter-constrained call rule that fires on any
// element carrying an attribute whose name matches ^on[a-z]+$.
func TestHTML_KwargNameMatches(t *testing.T) {
	rule := &rules.Rule{
		ID: "ZS-HTML-003", Language: core.LangHTML,
		Severity: core.SeverityMedium, Confidence: core.ConfidenceHigh,
		Match: rules.MatchPattern{
			Kind:    string(ir.NodeKindCall),
			Filters: []rules.Filter{{Kwarg: &rules.KwargPattern{NamePattern: "^on[a-z]+$"}}},
		},
	}
	if n := matchHTML(t, rule, htmlElement("button", [][2]string{{"onclick", "steal()"}})); n != 1 {
		t.Errorf("onclick should fire: got %d matches, want 1", n)
	}
	if n := matchHTML(t, rule, htmlElement("div", [][2]string{{"class", "x"}, {"id", "y"}})); n != 0 {
		t.Errorf("no handler should not fire: got %d matches, want 0", n)
	}
}

// TestHTML_NotWithNestedKwarg verifies the reverse-tabnabbing rule shape
// (ZS-HTML-001): kwarg target=_blank AND not(kwarg rel~noopener). This exercises
// the recursive `not` sub-pattern filter conversion.
func TestHTML_NotWithNestedKwarg(t *testing.T) {
	rule := &rules.Rule{
		ID: "ZS-HTML-001", Language: core.LangHTML,
		Severity: core.SeverityMedium, Confidence: core.ConfidenceMedium,
		Match: rules.MatchPattern{
			Kind: string(ir.NodeKindCall), Callee: "a",
			Filters: []rules.Filter{
				{Kwarg: &rules.KwargPattern{Name: "target", ValuePattern: "(?i)^_blank$"}},
				{Not: &rules.MatchPattern{
					Kind:    string(ir.NodeKindCall),
					Filters: []rules.Filter{{Kwarg: &rules.KwargPattern{Name: "rel", ValuePattern: "(?i)noopener"}}},
				}},
			},
		},
	}
	// target=_blank, no rel → vulnerable, fires.
	if n := matchHTML(t, rule, htmlElement("a", [][2]string{{"href", "/x"}, {"target", "_blank"}})); n != 1 {
		t.Errorf("target=_blank without rel should fire: got %d, want 1", n)
	}
	// target=_blank with rel=noopener → safe, does not fire.
	if n := matchHTML(t, rule, htmlElement("a", [][2]string{{"target", "_blank"}, {"rel", "noopener noreferrer"}})); n != 0 {
		t.Errorf("rel=noopener should be safe: got %d, want 0", n)
	}
	// no target=_blank → does not fire.
	if n := matchHTML(t, rule, htmlElement("a", [][2]string{{"href", "/x"}})); n != 0 {
		t.Errorf("no target=_blank should not fire: got %d, want 0", n)
	}
}
