//go:build cgo

package engine_test

import (
	"context"
	"testing"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/analyzer"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/engine"
	htmlparser "github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/parser/html"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/rules"
)

func loadHTMLRules(t *testing.T) *engine.RuleIndex {
	t.Helper()
	loader := rules.NewLoader(rules.EmbeddedFS)
	allRules, err := loader.LoadDir("data/html")
	if err != nil {
		t.Fatalf("load html rules: %v", err)
	}
	return engine.BuildIndex(allRules)
}

func matchHTMLSource(t *testing.T, idx *engine.RuleIndex, src string) []engine.MatchResult {
	t.Helper()
	builder := htmlparser.NewIRBuilder()
	irFile, _, err := builder.Build("test.html", []byte(src))
	if err != nil {
		t.Fatalf("build IR: %v", err)
	}
	ar, err := analyzer.New(false).Analyze(context.Background(), irFile)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	mc := &engine.MatchContext{Index: idx, File: ar}
	results, err := engine.New().Match(context.Background(), mc)
	if err != nil {
		t.Fatalf("match: %v", err)
	}
	return results
}

// TestIntegration_HTMLRulesFire checks each ZS-HTML rule fires on a minimal
// vulnerable snippet.
func TestIntegration_HTMLRulesFire(t *testing.T) {
	idx := loadHTMLRules(t)
	cases := []struct {
		rule string
		src  string
	}{
		{"ZS-HTML-001", `<a href="https://x.com" target="_blank">x</a>`},
		{"ZS-HTML-002", `<a href="javascript:alert(1)">x</a>`},
		{"ZS-HTML-003", `<button onclick="f()">x</button>`},
		{"ZS-HTML-004", `<iframe src="https://x.com"></iframe>`},
		{"ZS-HTML-005", `<script src="https://cdn.x.com/a.js"></script>`},
		{"ZS-HTML-006", `<img src="http://x.com/a.png">`},
		{"ZS-HTML-007", `<form action="http://x.com/login"></form>`},
		{"ZS-HTML-008", `<input type="password" autocomplete="on">`},
		{"ZS-HTML-009", `<meta http-equiv="refresh" content="0;url=http://evil.com">`},
		{"ZS-HTML-010", `<iframe src="https://x.com" sandbox="allow-scripts allow-same-origin"></iframe>`},
	}
	for _, c := range cases {
		if !hasRule(matchHTMLSource(t, idx, c.src), c.rule) {
			t.Errorf("%s: expected to fire on %q", c.rule, c.src)
		}
	}
}

// TestIntegration_HTMLRulesStaySilent checks the safe counterpart of each rule
// does not fire.
func TestIntegration_HTMLRulesStaySilent(t *testing.T) {
	idx := loadHTMLRules(t)
	cases := []struct {
		rule string
		src  string
	}{
		{"ZS-HTML-001", `<a href="https://x.com" target="_blank" rel="noopener">x</a>`},
		{"ZS-HTML-002", `<a href="https://x.com/page">x</a>`},
		{"ZS-HTML-003", `<button class="btn">x</button>`},
		{"ZS-HTML-004", `<iframe src="https://x.com" sandbox="allow-forms"></iframe>`},
		{"ZS-HTML-005", `<script src="https://cdn.x.com/a.js" integrity="sha384-abc"></script>`},
		{"ZS-HTML-006", `<img src="https://x.com/a.png">`},
		{"ZS-HTML-007", `<form action="https://x.com/login"></form>`},
		{"ZS-HTML-008", `<input type="password" autocomplete="new-password">`},
		{"ZS-HTML-009", `<meta charset="utf-8">`},
		{"ZS-HTML-010", `<iframe src="https://x.com" sandbox="allow-scripts"></iframe>`},
	}
	for _, c := range cases {
		if hasRule(matchHTMLSource(t, idx, c.src), c.rule) {
			t.Errorf("%s: expected NOT to fire on safe snippet %q", c.rule, c.src)
		}
	}
}
