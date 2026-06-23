package findings_test

import (
	"testing"

	"github.com/zerostrike/scanner/internal/analyzer"
	"github.com/zerostrike/scanner/internal/core"
	"github.com/zerostrike/scanner/internal/engine"
	"github.com/zerostrike/scanner/internal/findings"
	"github.com/zerostrike/scanner/internal/ir"
	"github.com/zerostrike/scanner/internal/rules"
	"github.com/zerostrike/scanner/internal/symboltable"
)

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
	f1 := findings.BuildFinding(engine.MatchResult{Rule: rule, Node: nodeAt10}, mc)

	// Same finding shifted to line 15 (blank line inserted above)
	nodeAt15 := &ir.IRNode{
		Kind:     ir.NodeKindCall,
		Text:     callText,
		Location: core.Location{File: "test.py", StartLine: 15, EndLine: 15},
	}
	f2 := findings.BuildFinding(engine.MatchResult{Rule: rule, Node: nodeAt15}, mc)

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
