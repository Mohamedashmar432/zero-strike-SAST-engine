package pipeline

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"sync"

	"github.com/zerostrike/scanner/internal/analyzer"
	"github.com/zerostrike/scanner/internal/core"
	"github.com/zerostrike/scanner/internal/detector"
	"github.com/zerostrike/scanner/internal/engine"
	"github.com/zerostrike/scanner/internal/findings"
	"github.com/zerostrike/scanner/internal/ir"
	pythonparser "github.com/zerostrike/scanner/internal/parser/python"
	"github.com/zerostrike/scanner/internal/rules"
	"github.com/zerostrike/scanner/internal/walker"
)

// ScanResult holds the results of a completed scan.
type ScanResult struct {
	Findings     []core.Finding
	Diagnostics  []scanDiagnostic
	FilesScanned int
	FilesSkipped int
}

type scanDiagnostic struct {
	File    string
	Message string
}

// ScanPipeline orchestrates the full scan lifecycle.
type ScanPipeline struct {
	config    ScanConfig
	walker    walker.Walker
	detector  detector.Detector
	eng       engine.Engine
	ruleIndex *engine.RuleIndex
	collector findings.Collector
	dedup     findings.Deduplicator
}

// New creates a ScanPipeline. Returns an error if rules fail to load or validate.
func New(cfg ScanConfig) (*ScanPipeline, error) {
	fsys, dir := rulesFS(cfg), rulesDir(cfg)
	allRules, err := rules.NewLoader(fsys).LoadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("pipeline: load rules: %w", err)
	}

	v := rules.NewValidator()
	for _, r := range allRules {
		if errs := v.Validate(r); len(errs) > 0 {
			return nil, fmt.Errorf("pipeline: invalid rule %s: %v", r.ID, errs)
		}
	}

	idx := engine.BuildIndex(allRules)

	return &ScanPipeline{
		config:    cfg,
		walker:    walker.NewWalker(nil),
		detector:  detector.NewDetector(),
		eng:       engine.New(),
		ruleIndex: idx,
		collector: findings.NewCollector(),
		dedup:     findings.NewDeduplicator(),
	}, nil
}

// rulesFS returns the fs.FS to load rules from.
// If RulesDir is set, uses the OS filesystem; otherwise uses the embedded FS.
func rulesFS(cfg ScanConfig) fs.FS {
	if cfg.RulesDir != "" {
		return os.DirFS(cfg.RulesDir)
	}
	return rules.EmbeddedFS
}

// rulesDir returns the directory argument for LoadDir.
// ponytail: hardcoded to "data/python" for embedded — multi-language deferred to Sprint 4+
func rulesDir(cfg ScanConfig) string {
	if cfg.RulesDir != "" {
		return "."
	}
	return "data/python"
}

// Run executes the scan and returns results.
// It never makes network calls; upload is a separate stage.
func (p *ScanPipeline) Run(ctx context.Context) (*ScanResult, error) {
	fileCh, errCh := p.walker.Walk(p.config.RootPath)

	var (
		mu       sync.Mutex
		result   ScanResult
		allFiles []walker.FileEntry
	)

	for entry := range fileCh {
		allFiles = append(allFiles, entry)
	}
	if err := <-errCh; err != nil {
		return nil, fmt.Errorf("walk failed: %w", err)
	}

	fileQueue := make(chan walker.FileEntry, len(allFiles))
	for _, f := range allFiles {
		fileQueue <- f
	}
	close(fileQueue)

	pipeErrs := make(chan error, 10)
	workerPool(ctx, fileQueue, p.config.WorkerCount, func(entry walker.FileEntry) error {
		return p.processFile(ctx, entry, &mu, &result)
	}, pipeErrs)
	close(pipeErrs)

	for err := range pipeErrs {
		if err != nil {
			result.Diagnostics = append(result.Diagnostics, scanDiagnostic{Message: err.Error()})
		}
	}

	result.Findings = p.dedup.Deduplicate(p.collector.All())
	return &result, nil
}

// processFile handles a single file through the parse → IR → analyze → match pipeline.
func (p *ScanPipeline) processFile(ctx context.Context, entry walker.FileEntry, mu *sync.Mutex, result *ScanResult) error {
	source, err := os.ReadFile(entry.Path)
	if err != nil {
		return nil // skip unreadable files silently
	}

	lang := p.detector.Detect(entry.Path, source)
	if !lang.IsKnown() {
		mu.Lock()
		result.FilesSkipped++
		mu.Unlock()
		return nil
	}

	irFile, warnings, err := p.buildIR(ctx, entry.Path, lang, source)
	if err != nil {
		mu.Lock()
		result.Diagnostics = append(result.Diagnostics, scanDiagnostic{File: entry.Path, Message: err.Error()})
		mu.Unlock()
		return nil
	}
	for _, w := range warnings {
		mu.Lock()
		result.Diagnostics = append(result.Diagnostics, scanDiagnostic{File: entry.Path, Message: w})
		mu.Unlock()
	}

	analysisResult, err := analyzer.New().Analyze(ctx, irFile)
	if err != nil {
		mu.Lock()
		result.Diagnostics = append(result.Diagnostics, scanDiagnostic{File: entry.Path, Message: err.Error()})
		mu.Unlock()
		return nil
	}

	mc := &engine.MatchContext{
		Index:   p.ruleIndex,
		File:    analysisResult,
		Project: &engine.Project{Root: p.config.RootPath},
	}
	matchResults, err := p.eng.Match(ctx, mc)
	if err != nil {
		mu.Lock()
		result.Diagnostics = append(result.Diagnostics, scanDiagnostic{File: entry.Path, Message: err.Error()})
		mu.Unlock()
		return nil
	}

	fileFindings := make([]core.Finding, 0, len(matchResults))
	for _, mr := range matchResults {
		fileFindings = append(fileFindings, findings.BuildFinding(mr, mc))
	}
	p.collector.Add(fileFindings)

	mu.Lock()
	result.FilesScanned++
	mu.Unlock()
	return nil
}

// buildIR parses source and builds an IRFile, returning any build warnings.
func (p *ScanPipeline) buildIR(ctx context.Context, path string, lang core.Language, source []byte) (*ir.IRFile, []string, error) {
	switch lang {
	case core.LangPython:
		parser := pythonparser.New()
		parseResult, err := parser.Parse(ctx, source)
		if err != nil {
			return nil, nil, fmt.Errorf("parse %s: %w", path, err)
		}
		builder := pythonparser.NewIRBuilder()
		irFile, warnings, buildErr := builder.Build(path, parseResult.Source)
		return irFile, warnings, buildErr
	default:
		return nil, nil, fmt.Errorf("no parser for language %s", lang)
	}
}
