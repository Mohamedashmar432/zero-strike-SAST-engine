package analyzer

import (
	"context"

	"github.com/zerostrike/scanner/internal/analyzer/taint"
	"github.com/zerostrike/scanner/internal/core"
	"github.com/zerostrike/scanner/internal/graph"
	"github.com/zerostrike/scanner/internal/ir"
	"github.com/zerostrike/scanner/internal/symboltable"
)

// New returns the default Analyzer implementation. enableGraphs opts into
// building the CFG/DFG graph layer (Python IR only, this sprint — see
// internal/graph) for path-sensitive taint reporting; leave it false for the
// pre-existing flow-insensitive-only behavior at zero extra cost.
func New(enableGraphs bool) Analyzer { return &defaultAnalyzer{enableGraphs: enableGraphs} }

type defaultAnalyzer struct {
	enableGraphs bool
}

func (a *defaultAnalyzer) Analyze(_ context.Context, file *ir.IRFile) (*AnalysisResult, error) {
	if file == nil {
		return &AnalysisResult{}, nil
	}
	symbols := symboltable.NewBuilder().Build(file)

	var cfg *graph.CFG
	var dfg *graph.DFG
	if a.enableGraphs && file.Language == core.LangPython && file.Root != nil {
		cfg = graph.NewCFG(file.Root)
		dfg = graph.NewDFG(file.Root, cfg)
	}

	tc := taint.BuildContext(file, symbols, dfg)
	return &AnalysisResult{
		File:         file.Path,
		IR:           file,
		Symbols:      symbols,
		CFG:          cfg,
		DFG:          dfg,
		TaintedVars:  tc.Tainted,
		TaintReasons: tc.Reasons,
		TaintPaths:   tc.Paths,
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
	// TaintReasons holds a human-readable reason for each tainted variable in
	// TaintedVars — the source expression, propagation origin, or summarized
	// call that most recently caused its taint verdict (see
	// internal/analyzer/taint.BuildContext). Keyed by the same variable
	// names as TaintedVars; only set for variables where TaintedVars is true.
	TaintReasons map[string]string
	// TaintPaths holds the source-to-sink location chain for each tainted
	// variable (see internal/analyzer/taint.Result.Paths). Nil unless
	// --enable-graphs was set and the file's language has graph support
	// (Python only, this sprint).
	TaintPaths  map[string][]core.Location
	Diagnostics []Diagnostic
}

// Analyzer runs analysis passes over an IRFile to produce an AnalysisResult.
type Analyzer interface {
	Analyze(ctx context.Context, file *ir.IRFile) (*AnalysisResult, error)
}
