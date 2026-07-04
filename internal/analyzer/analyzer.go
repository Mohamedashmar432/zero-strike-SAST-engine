package analyzer

import (
	"context"

	"github.com/zerostrike/scanner/internal/analyzer/taint"
	"github.com/zerostrike/scanner/internal/core"
	"github.com/zerostrike/scanner/internal/graph"
	"github.com/zerostrike/scanner/internal/ir"
	"github.com/zerostrike/scanner/internal/symboltable"
)

// New returns the default Analyzer implementation.
func New() Analyzer { return &defaultAnalyzer{} }

type defaultAnalyzer struct{}

func (a *defaultAnalyzer) Analyze(_ context.Context, file *ir.IRFile) (*AnalysisResult, error) {
	if file == nil {
		return &AnalysisResult{}, nil
	}
	symbols := symboltable.NewBuilder().Build(file)
	return &AnalysisResult{
		File:        file.Path,
		IR:          file,
		Symbols:     symbols,
		TaintedVars: taint.Build(file, symbols),
	}, nil
}

// Diagnostic is a non-finding observation from the analysis pass
// (e.g., parse errors, skipped generated files, unsupported syntax).
type Diagnostic struct {
	Severity string // "error" | "warning" | "info"
	Message  string
	Location *core.Location
}

// TaintFlow tracks data from a taint source to a taint sink.
// Sprint 8 will populate this from real DFG analysis.
type TaintFlow struct {
	Source core.Location
	Sink   core.Location
	Path   []core.Location
}

// AnalysisResult holds all analysis data for a single source file.
type AnalysisResult struct {
	File       string
	IR         *ir.IRFile
	Symbols    symboltable.SymbolTable
	CFG        *graph.CFG       // nil unless --enable-graphs flag is set
	DFG        *graph.DFG       // nil unless --enable-graphs flag is set
	CallGraph  *graph.CallGraph // nil unless --enable-graphs flag is set
	TaintFlows []TaintFlow      // nil in Sprint 1
	// TaintedVars holds variable names whose value may originate from an
	// untrusted source (see internal/analyzer/taint). File-scoped, with
	// per-language source/sanitizer patterns (Python/JS/TS/C#) and same-file
	// function summaries — see package taint's doc comment for the ceiling.
	TaintedVars map[string]bool
	Diagnostics []Diagnostic
}

// Analyzer runs analysis passes over an IRFile to produce an AnalysisResult.
type Analyzer interface {
	Analyze(ctx context.Context, file *ir.IRFile) (*AnalysisResult, error)
}
