package findings_test

import (
	"testing"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/analyzer"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/engine"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/findings"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/ir"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/rules"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/symboltable"
)

func TestBuildSecretFinding_Fingerprint(t *testing.T) {
	rawSecret := []byte("AKIAIOSFODNN7EXAMPLE")
	f1 := findings.BuildSecretFinding("aws-access-key", "ZS-SEC-001", "AWS Key", "found", "a.py", 1, rawSecret, 3.5, core.SeverityCritical)
	f2 := findings.BuildSecretFinding("aws-access-key", "ZS-SEC-001", "AWS Key", "found", "b.py", 5, rawSecret, 3.5, core.SeverityCritical)
	if f1.Fingerprint != f2.Fingerprint {
		t.Errorf("same secret in two files should produce same fingerprint: %q vs %q", f1.Fingerprint, f2.Fingerprint)
	}
	if f1.Kind != core.FindingKindSecret {
		t.Errorf("Kind = %q, want secret", f1.Kind)
	}
	if f1.Secret == nil {
		t.Fatal("Secret payload must not be nil")
	}
	if f1.Secret.DetectorID != "aws-access-key" {
		t.Errorf("DetectorID = %q, want aws-access-key", f1.Secret.DetectorID)
	}
}

func TestBuildDependencyFinding_Fingerprint(t *testing.T) {
	dep := findings.DependencyInput{
		Ecosystem: "PyPI", Package: "requests", InstalledVersion: "2.0.0",
		VulnerableRange: "<2.31.0", FixedVersion: "2.31.0",
		Manifest: "requirements.txt", Direct: true,
	}
	advisoryIDs := []string{"GHSA-1234-abcd-5678", "CVE-2024-1234"}
	f1 := findings.BuildDependencyFinding("ZS-SCA-001", "Vuln Dep", "msg", dep, advisoryIDs, core.SeverityHigh, core.ConfidenceHigh)
	f2 := findings.BuildDependencyFinding("ZS-SCA-001", "Vuln Dep", "msg", dep, advisoryIDs, core.SeverityHigh, core.ConfidenceHigh)
	if f1.Fingerprint != f2.Fingerprint {
		t.Errorf("same dep+advisory should produce same fingerprint: %q vs %q", f1.Fingerprint, f2.Fingerprint)
	}
	if f1.Kind != core.FindingKindSCA {
		t.Errorf("Kind = %q, want sca", f1.Kind)
	}
	if f1.Dependency == nil {
		t.Fatal("Dependency payload must not be nil")
	}
	if f1.Dependency.Package != "requests" {
		t.Errorf("Package = %q, want requests", f1.Dependency.Package)
	}
}

// TestFingerprint_StableAcrossLineChanges verifies C2: the Fingerprint must be
// identical for the same logical finding even when its line number changes
// (e.g., a blank line was inserted above it).
func TestFingerprint_StableAcrossLineChanges(t *testing.T) {
	rule := &rules.Rule{
		ID:         "ZS-PY-001",
		Name:       "eval usage",
		Severity:   core.SeverityHigh,
		Confidence: core.ConfidenceHigh,
	}
	callText := "eval(user_input)"

	irRoot := &ir.IRNode{Kind: ir.NodeKindModule, Location: core.Location{StartLine: 1, EndLine: 20}}
	irFile := &ir.IRFile{Language: core.LangPython, Path: "test.py", Root: irRoot}
	syms := symboltable.NewBuilder().Build(irFile)
	mc := &engine.MatchContext{
		File: &analyzer.AnalysisResult{IR: irFile, Symbols: syms},
	}

	// Finding at line 10
	nodeAt10 := &ir.IRNode{
		Kind:     ir.NodeKindCall,
		Text:     callText,
		Location: core.Location{File: "test.py", StartLine: 10, EndLine: 10},
	}
	f1 := findings.BuildFinding(engine.MatchResult{Rule: rule, Node: nodeAt10}, mc, nil)

	// Same finding shifted to line 15 (blank line inserted above)
	nodeAt15 := &ir.IRNode{
		Kind:     ir.NodeKindCall,
		Text:     callText,
		Location: core.Location{File: "test.py", StartLine: 15, EndLine: 15},
	}
	f2 := findings.BuildFinding(engine.MatchResult{Rule: rule, Node: nodeAt15}, mc, nil)

	if f1.Fingerprint != f2.Fingerprint {
		t.Errorf("Fingerprint changed when line number changed: %q vs %q", f1.Fingerprint, f2.Fingerprint)
	}
	if f1.Location.StartLine == f2.Location.StartLine {
		t.Error("Location.StartLine should differ between the two findings")
	}
	if f1.Fingerprint == "" {
		t.Error("Fingerprint must not be empty")
	}
}

// TestBuildFinding_RationaleAndRemediation verifies that Finding.Rationale and
// Finding.Remediation are populated from the matched rule's Rationale and
// FixSuggestion fields, and that a rule without them produces an empty (not
// crashing) result.
func TestBuildFinding_RationaleAndRemediation(t *testing.T) {
	irRoot := &ir.IRNode{Kind: ir.NodeKindModule, Location: core.Location{StartLine: 1, EndLine: 20}}
	irFile := &ir.IRFile{Language: core.LangPython, Path: "test.py", Root: irRoot}
	syms := symboltable.NewBuilder().Build(irFile)
	mc := &engine.MatchContext{
		File: &analyzer.AnalysisResult{IR: irFile, Symbols: syms},
	}
	node := &ir.IRNode{
		Kind:     ir.NodeKindCall,
		Text:     "eval(user_input)",
		Location: core.Location{File: "test.py", StartLine: 10, EndLine: 10},
	}

	t.Run("populated rule metadata", func(t *testing.T) {
		rule := &rules.Rule{
			ID:            "ZS-PY-001",
			Name:          "eval usage",
			Severity:      core.SeverityHigh,
			Confidence:    core.ConfidenceHigh,
			Rationale:     "eval() executes arbitrary code, allowing injection if input is attacker-controlled.",
			Description:   "Detects calls to the eval() builtin regardless of taint.",
			FixSuggestion: "Avoid eval(); use ast.literal_eval() or a safe parser instead.",
		}
		f := findings.BuildFinding(engine.MatchResult{Rule: rule, Node: node}, mc, nil)
		if f.Rationale != rule.Rationale {
			t.Errorf("Rationale = %q, want %q", f.Rationale, rule.Rationale)
		}
		if f.Description != rule.Description {
			t.Errorf("Description = %q, want %q", f.Description, rule.Description)
		}
		if f.Remediation != rule.FixSuggestion {
			t.Errorf("Remediation = %q, want %q", f.Remediation, rule.FixSuggestion)
		}
	})

	t.Run("empty rule metadata", func(t *testing.T) {
		rule := &rules.Rule{
			ID:         "ZS-PY-002",
			Name:       "no metadata rule",
			Severity:   core.SeverityHigh,
			Confidence: core.ConfidenceHigh,
		}
		f := findings.BuildFinding(engine.MatchResult{Rule: rule, Node: node}, mc, nil)
		if f.Rationale != "" {
			t.Errorf("Rationale = %q, want empty", f.Rationale)
		}
		if f.Remediation != "" {
			t.Errorf("Remediation = %q, want empty", f.Remediation)
		}
	})
}

// TestBuildFinding_TaintContext verifies that Finding.TaintContext is
// populated with the source variable, source expression (from
// AnalysisResult.TaintReasons), and sink (rule callee or assignment LHS)
// when MatchResult.TaintedVar is non-empty, and stays nil otherwise.
func TestBuildFinding_TaintContext(t *testing.T) {
	irRoot := &ir.IRNode{Kind: ir.NodeKindModule, Location: core.Location{StartLine: 1, EndLine: 20}}
	irFile := &ir.IRFile{Language: core.LangPython, Path: "test.py", Root: irRoot}
	syms := symboltable.NewBuilder().Build(irFile)

	t.Run("taint-gated call sink", func(t *testing.T) {
		mc := &engine.MatchContext{
			File: &analyzer.AnalysisResult{
				IR:      irFile,
				Symbols: syms,
				TaintReasons: map[string]string{
					"query": "request.args.get('id')",
				},
			},
		}
		rule := &rules.Rule{
			ID:         "ZS-PY-003",
			Name:       "sql injection",
			Severity:   core.SeverityHigh,
			Confidence: core.ConfidenceHigh,
			Match:      rules.MatchPattern{Kind: string(ir.NodeKindCall), Callee: "cursor.execute"},
		}
		node := &ir.IRNode{
			Kind:     ir.NodeKindCall,
			Text:     "cursor.execute(query)",
			Location: core.Location{File: "test.py", StartLine: 12, EndLine: 12},
		}
		f := findings.BuildFinding(engine.MatchResult{Rule: rule, Node: node, TaintedVar: "query"}, mc, nil)
		if f.TaintContext == nil {
			t.Fatal("expected TaintContext to be populated")
		}
		if f.TaintContext.SourceVar != "query" {
			t.Errorf("SourceVar = %q, want %q", f.TaintContext.SourceVar, "query")
		}
		if f.TaintContext.SourceExpr != "request.args.get('id')" {
			t.Errorf("SourceExpr = %q, want %q", f.TaintContext.SourceExpr, "request.args.get('id')")
		}
		if f.TaintContext.Sink != "cursor.execute" {
			t.Errorf("Sink = %q, want %q", f.TaintContext.Sink, "cursor.execute")
		}
	})

	t.Run("taint-gated assignment sink falls back to LHS", func(t *testing.T) {
		mc := &engine.MatchContext{
			File: &analyzer.AnalysisResult{
				IR:      irFile,
				Symbols: syms,
				TaintReasons: map[string]string{
					"userInput": "req.query.name",
				},
			},
		}
		rule := &rules.Rule{
			ID:         "ZS-JS-001",
			Name:       "dom xss",
			Severity:   core.SeverityHigh,
			Confidence: core.ConfidenceHigh,
			Match:      rules.MatchPattern{Kind: string(ir.NodeKindAssignment), LHSIdentifier: "innerHTML"},
		}
		node := &ir.IRNode{
			Kind:     ir.NodeKindAssignment,
			Text:     "el.innerHTML = userInput",
			Attrs:    map[string]any{"lhs": "el.innerHTML"},
			Location: core.Location{File: "test.py", StartLine: 12, EndLine: 12},
		}
		f := findings.BuildFinding(engine.MatchResult{Rule: rule, Node: node, TaintedVar: "userInput"}, mc, nil)
		if f.TaintContext == nil {
			t.Fatal("expected TaintContext to be populated")
		}
		if f.TaintContext.Sink != "el.innerHTML" {
			t.Errorf("Sink = %q, want LHS fallback %q", f.TaintContext.Sink, "el.innerHTML")
		}
	})

	t.Run("tainted var missing from TaintReasons degrades to empty SourceExpr", func(t *testing.T) {
		mc := &engine.MatchContext{
			File: &analyzer.AnalysisResult{IR: irFile, Symbols: syms}, // TaintReasons left nil
		}
		rule := &rules.Rule{
			ID:         "ZS-PY-003",
			Name:       "sql injection",
			Severity:   core.SeverityHigh,
			Confidence: core.ConfidenceHigh,
			Match:      rules.MatchPattern{Kind: string(ir.NodeKindCall), Callee: "cursor.execute"},
		}
		node := &ir.IRNode{
			Kind:     ir.NodeKindCall,
			Text:     "cursor.execute(query)",
			Location: core.Location{File: "test.py", StartLine: 12, EndLine: 12},
		}
		f := findings.BuildFinding(engine.MatchResult{Rule: rule, Node: node, TaintedVar: "query"}, mc, nil)
		if f.TaintContext == nil {
			t.Fatal("expected TaintContext to be populated when TaintedVar is set, even without a TaintReasons entry")
		}
		if f.TaintContext.SourceVar != "query" {
			t.Errorf("SourceVar = %q, want %q", f.TaintContext.SourceVar, "query")
		}
		if f.TaintContext.SourceExpr != "" {
			t.Errorf("SourceExpr = %q, want empty when TaintReasons has no entry for the tainted var", f.TaintContext.SourceExpr)
		}
		if f.TaintContext.Sink != "cursor.execute" {
			t.Errorf("Sink = %q, want %q", f.TaintContext.Sink, "cursor.execute")
		}
	})

	t.Run("no tainted var means nil TaintContext", func(t *testing.T) {
		mc := &engine.MatchContext{
			File: &analyzer.AnalysisResult{IR: irFile, Symbols: syms},
		}
		rule := &rules.Rule{
			ID:         "ZS-PY-004",
			Name:       "eval usage",
			Severity:   core.SeverityHigh,
			Confidence: core.ConfidenceHigh,
		}
		node := &ir.IRNode{
			Kind:     ir.NodeKindCall,
			Text:     "eval(user_input)",
			Location: core.Location{File: "test.py", StartLine: 10, EndLine: 10},
		}
		f := findings.BuildFinding(engine.MatchResult{Rule: rule, Node: node}, mc, nil)
		if f.TaintContext != nil {
			t.Errorf("TaintContext = %+v, want nil when TaintedVar is empty", f.TaintContext)
		}
	})
}

// TestBuildFinding_SnippetFallsBackToSourceLines verifies the fix for the bug where every real
// finding had Evidence == nil: node.Text is only populated for tree-sitter leaf nodes, but every
// rule matches on a compound node (call, assignment, try, ...), so node.Text is always "" in
// practice. BuildFinding must fall back to slicing the snippet out of the file's source bytes
// using the match's line range.
func TestBuildFinding_SnippetFallsBackToSourceLines(t *testing.T) {
	source := []byte("import requests\n\ndef fetch(url):\n    requests.get(url, verify=False)\n")

	irRoot := &ir.IRNode{Kind: ir.NodeKindModule, Location: core.Location{StartLine: 1, EndLine: 4}}
	irFile := &ir.IRFile{Language: core.LangPython, Path: "test.py", Root: irRoot}
	syms := symboltable.NewBuilder().Build(irFile)
	mc := &engine.MatchContext{File: &analyzer.AnalysisResult{IR: irFile, Symbols: syms}}

	rule := &rules.Rule{
		ID:         "ZS-PY-025",
		Name:       "SSRF",
		Severity:   core.SeverityHigh,
		Confidence: core.ConfidenceHigh,
		Match:      rules.MatchPattern{Kind: string(ir.NodeKindCall), Callee: "requests.get"},
	}
	// Text is deliberately empty here: this is what the real parser produces for a compound
	// "call" node (see internal/parser/python/builder.go - Text is leaf-only).
	node := &ir.IRNode{
		Kind:     ir.NodeKindCall,
		Text:     "",
		Location: core.Location{File: "test.py", StartLine: 4, EndLine: 4},
	}

	f := findings.BuildFinding(engine.MatchResult{Rule: rule, Node: node}, mc, source)

	wantSnippet := "    requests.get(url, verify=False)"
	if len(f.Evidence) != 1 {
		t.Fatalf("Evidence = %+v, want exactly one entry", f.Evidence)
	}
	if f.Evidence[0].Snippet != wantSnippet {
		t.Errorf("Snippet = %q, want %q", f.Evidence[0].Snippet, wantSnippet)
	}
	if f.Evidence[0].StartLine != 4 || f.Evidence[0].EndLine != 4 {
		t.Errorf("Evidence line range = %d-%d, want 4-4", f.Evidence[0].StartLine, f.Evidence[0].EndLine)
	}
	if f.Fingerprint == "" {
		t.Error("Fingerprint must not be empty")
	}

	// Same rule, same enclosing scope, different line/snippet must NOT collide: this is the
	// fingerprint half of the same bug (computeFingerprint was also fed the always-empty node.Text).
	node2 := &ir.IRNode{
		Kind:     ir.NodeKindCall,
		Text:     "",
		Location: core.Location{File: "test.py", StartLine: 4, EndLine: 4},
	}
	source2 := []byte("import requests\n\ndef fetch(url):\n    requests.get(other_url, verify=False)\n")
	f2 := findings.BuildFinding(engine.MatchResult{Rule: rule, Node: node2}, mc, source2)
	if f.Fingerprint == f2.Fingerprint {
		t.Errorf("distinct snippets produced the same fingerprint %q — fingerprint is still collapsing on empty node.Text", f.Fingerprint)
	}
}
