//go:build cgo

package sast

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"sync"

	"github.com/zerostrike/scanner/internal/analyzer"
	"github.com/zerostrike/scanner/internal/core"
	"github.com/zerostrike/scanner/internal/detector"
	"github.com/zerostrike/scanner/internal/engine"
	"github.com/zerostrike/scanner/internal/findings"
	"github.com/zerostrike/scanner/internal/ir"
	"github.com/zerostrike/scanner/internal/langreg"
	"github.com/zerostrike/scanner/internal/rules"
	"github.com/zerostrike/scanner/internal/walker"

	// Blank imports run each language package's init() registration with
	// langreg. Linking the (CGo) SAST scanner links its languages, so every
	// consumer — the CLI binary and test binaries alike — gets a populated
	// registry without wiring it up itself.
	_ "github.com/zerostrike/scanner/internal/parser/csharp"
	_ "github.com/zerostrike/scanner/internal/parser/javascript"
	_ "github.com/zerostrike/scanner/internal/parser/python"
	_ "github.com/zerostrike/scanner/internal/parser/typescript"
)

// SASTScanner runs rule-based pattern matching over AST IR.
type SASTScanner struct {
	eng       engine.Engine
	ruleIndex *engine.RuleIndex
	det       detector.Detector
	rootPath  string
}

// New creates a SASTScanner from a pre-validated rule set.
func New(allRules []*rules.Rule, rootPath string) *SASTScanner {
	return &SASTScanner{
		eng:       engine.New(),
		ruleIndex: engine.BuildIndex(allRules),
		det:       detector.NewDetector(),
		rootPath:  rootPath,
	}
}

func (s *SASTScanner) Name() string { return "sast" }

func (s *SASTScanner) Accepts(entry walker.FileEntry) bool {
	return !entry.IsBinary
}

func (s *SASTScanner) Scan(ctx context.Context, files []walker.FileEntry) ([]core.Finding, []analyzer.Diagnostic, error) {
	type fileResult struct {
		fs    []core.Finding
		diags []analyzer.Diagnostic
	}

	resultCh := make(chan fileResult, len(files))

	fileQueue := make(chan walker.FileEntry, len(files))
	for _, f := range files {
		fileQueue <- f
	}
	close(fileQueue)

	numWorkers := runtime.NumCPU()
	var wg sync.WaitGroup
	for range numWorkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for entry := range fileQueue {
				if ctx.Err() != nil {
					return
				}
				fs, diags := s.processFile(ctx, entry)
				resultCh <- fileResult{fs: fs, diags: diags}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	var allFindings []core.Finding
	var allDiags []analyzer.Diagnostic
	for r := range resultCh {
		allFindings = append(allFindings, r.fs...)
		allDiags = append(allDiags, r.diags...)
	}
	return allFindings, allDiags, nil
}

func (s *SASTScanner) processFile(ctx context.Context, entry walker.FileEntry) ([]core.Finding, []analyzer.Diagnostic) {
	source, err := os.ReadFile(entry.Path)
	if err != nil {
		return nil, nil
	}

	lang := s.det.Detect(entry.Path, source)
	if !lang.IsKnown() {
		return nil, nil
	}

	irFile, warnings, err := s.buildIR(ctx, entry.Path, lang, source)
	var diags []analyzer.Diagnostic
	if err != nil {
		diags = append(diags, analyzer.Diagnostic{Severity: "error", Message: err.Error(), Location: &core.Location{File: entry.Path}})
		return nil, diags
	}
	for _, w := range warnings {
		diags = append(diags, analyzer.Diagnostic{Severity: "warning", Message: w, Location: &core.Location{File: entry.Path}})
	}

	analysisResult, err := analyzer.New().Analyze(ctx, irFile)
	if err != nil {
		diags = append(diags, analyzer.Diagnostic{Severity: "error", Message: err.Error(), Location: &core.Location{File: entry.Path}})
		return nil, diags
	}

	mc := &engine.MatchContext{
		Index:   s.ruleIndex,
		File:    analysisResult,
		Project: &engine.Project{Root: s.rootPath},
	}
	matchResults, err := s.eng.Match(ctx, mc)
	if err != nil {
		diags = append(diags, analyzer.Diagnostic{Severity: "error", Message: err.Error(), Location: &core.Location{File: entry.Path}})
		return nil, diags
	}

	fileFindings := make([]core.Finding, 0, len(matchResults))
	for _, mr := range matchResults {
		fileFindings = append(fileFindings, findings.BuildFinding(mr, mc))
	}
	return fileFindings, diags
}

// buildIR dispatches to the registered language builder. The ctx parameter is
// currently unused (builders parse with context.Background() internally); it
// is kept to avoid call-site churn and for a future context-aware Build.
func (s *SASTScanner) buildIR(ctx context.Context, path string, lang core.Language, source []byte) (*ir.IRFile, []string, error) {
	_ = ctx
	entry, ok := langreg.Get(lang)
	if !ok {
		return nil, nil, fmt.Errorf("no parser registered for language %s", lang)
	}
	irFile, buildWarnings, buildErr := entry.NewBuilder().Build(path, source)
	warnings := make([]string, len(buildWarnings))
	for i, w := range buildWarnings {
		warnings[i] = w.Message
	}
	return irFile, warnings, buildErr
}
