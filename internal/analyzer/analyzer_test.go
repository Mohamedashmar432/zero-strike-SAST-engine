package analyzer_test

import (
	"context"
	"testing"

	"github.com/zerostrike/scanner/internal/analyzer"
	"github.com/zerostrike/scanner/internal/core"
	"github.com/zerostrike/scanner/internal/ir"
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

	result, err := analyzer.New().Analyze(context.Background(), irFile)
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
	result, err := analyzer.New().Analyze(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("result is nil")
	}
}
