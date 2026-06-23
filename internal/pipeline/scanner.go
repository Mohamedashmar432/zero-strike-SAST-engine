package pipeline

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/zerostrike/scanner/internal/analyzer"
	"github.com/zerostrike/scanner/internal/core"
	"github.com/zerostrike/scanner/internal/detector"
	"github.com/zerostrike/scanner/internal/ir"
	pythonparser "github.com/zerostrike/scanner/internal/parser/python"
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
	config   ScanConfig
	walker   walker.Walker
	detector detector.Detector
}

// New creates a ScanPipeline with the given config.
func New(cfg ScanConfig) *ScanPipeline {
	return &ScanPipeline{
		config:   cfg,
		walker:   walker.NewWalker(nil),
		detector: detector.NewDetector(),
	}
}

// Run executes the scan and returns results.
func (p *ScanPipeline) Run(ctx context.Context) (*ScanResult, error) {
	fileCh, errCh := p.walker.Walk(p.config.RootPath)

	var (
		mu       sync.Mutex
		result   ScanResult
		allFiles []walker.FileEntry
	)

	// Collect all files first (walker is non-blocking)
	for entry := range fileCh {
		allFiles = append(allFiles, entry)
	}
	if err := <-errCh; err != nil {
		return nil, fmt.Errorf("walk failed: %w", err)
	}

	// Process files in worker pool
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

	return &result, nil
}

// processFile handles a single file through the parse → IR pipeline.
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

	irFile, err := p.buildIR(ctx, entry.Path, lang, source)
	if err != nil {
		mu.Lock()
		result.Diagnostics = append(result.Diagnostics, scanDiagnostic{File: entry.Path, Message: err.Error()})
		mu.Unlock()
		return nil
	}

	analysisResult, err := analyzer.New().Analyze(ctx, irFile)
	if err != nil {
		mu.Lock()
		result.Diagnostics = append(result.Diagnostics, scanDiagnostic{File: entry.Path, Message: err.Error()})
		mu.Unlock()
		return nil
	}
	_ = analysisResult // rule matching comes in Sprint 3

	mu.Lock()
	result.FilesScanned++
	mu.Unlock()
	return nil
}

// buildIR parses source and builds an IRFile for the given language.
func (p *ScanPipeline) buildIR(ctx context.Context, path string, lang core.Language, source []byte) (*ir.IRFile, error) {
	switch lang {
	case core.LangPython:
		parser := pythonparser.New()
		parseResult, err := parser.Parse(ctx, source)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		builder := pythonparser.NewIRBuilder()
		return builder.Build(path, parseResult.Source)
	default:
		return nil, fmt.Errorf("no parser for language %s", lang)
	}
}
