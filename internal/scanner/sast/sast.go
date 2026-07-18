//go:build cgo

package sast

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"sync"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/analyzer"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/cache"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/detector"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/engine"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/findings"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/ir"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/langreg"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/rules"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/walker"

	// Blank imports run each language package's init() registration with
	// langreg. Linking the (CGo) SAST scanner links its languages, so every
	// consumer — the CLI binary and test binaries alike — gets a populated
	// registry without wiring it up itself.
	_ "github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/parser/csharp"
	_ "github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/parser/golang"
	_ "github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/parser/java"
	_ "github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/parser/javascript"
	_ "github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/parser/php"
	_ "github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/parser/python"
	_ "github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/parser/typescript"
)

// SASTScanner runs rule-based pattern matching over AST IR.
type SASTScanner struct {
	eng          engine.Engine
	ruleIndex    *engine.RuleIndex
	det          detector.Detector
	rootPath     string
	findingCache cache.FindingCache
	astCache     cache.ASTCache
	enableGraphs bool
}

// New creates a SASTScanner from a pre-validated rule set. findingCache and
// astCache are consulted/written on every processed file; pass
// cache.NoopCache{}/cache.NoopASTCache{} to disable caching (e.g. --no-cache).
// enableGraphs opts into CFG/DFG-based path-sensitive taint reporting (see
// internal/analyzer.New).
func New(allRules []*rules.Rule, rootPath string, findingCache cache.FindingCache, astCache cache.ASTCache, enableGraphs bool) *SASTScanner {
	return &SASTScanner{
		eng:          engine.New(),
		ruleIndex:    engine.BuildIndex(allRules),
		det:          detector.NewDetector(),
		rootPath:     rootPath,
		findingCache: findingCache,
		astCache:     astCache,
		enableGraphs: enableGraphs,
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

	contentHash := sha256Hex(source)

	// Finding-cache check: on a hit, skip language detection, parsing,
	// analysis, and matching entirely.
	//
	// NOTE: a finding-cache hit does NOT replay the original run's
	// build/analyze diagnostics (parse warnings, etc.) - only findings are
	// cached, not diagnostics. This is a deliberate, accepted simplification
	// (diagnostics are advisory, not correctness-critical), not an
	// oversight.
	//
	// NOTE: cached findings also carry Finding.ID from the run that produced
	// them, not a fresh uuid.New().String() for this run - deliberately, so
	// this cache doesn't need to rewrite every finding just to mint new IDs.
	// This is safe because ID is not this scanner's stable cross-run
	// identity: Fingerprint is (see core.Finding's doc comment), and nothing
	// downstream dedups/suppresses by ID.
	if e, ok := s.findingCache.Get(entry.Path); ok && e.SHA256 == contentHash {
		if cached, err := s.findingCache.GetFindings(entry.Path); err == nil {
			return cached, nil
		}
	}

	lang := s.det.Detect(entry.Path, source)
	if !lang.IsKnown() {
		return nil, nil
	}

	irFile, warnings, err := s.loadOrBuildIR(ctx, entry.Path, lang, source, contentHash)
	var diags []analyzer.Diagnostic
	if err != nil {
		diags = append(diags, analyzer.Diagnostic{Severity: "error", Message: err.Error(), Location: &core.Location{File: entry.Path}})
		return nil, diags
	}
	for _, w := range warnings {
		diags = append(diags, analyzer.Diagnostic{Severity: "warning", Message: w, Location: &core.Location{File: entry.Path}})
	}

	// Analysis and matching always run, whether irFile came from the AST
	// cache or a fresh parse: rules (and therefore match results) may have
	// changed even though the file's content - and its cached AST - has not.
	analysisResult, err := analyzer.New(s.enableGraphs).Analyze(ctx, irFile)
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
		fileFindings = append(fileFindings, findings.BuildFinding(mr, mc, source))
	}

	// Write-through to the finding cache. PutRecord stores the Entry and its
	// Findings as a single atomic write - unlike calling Set and PutFindings
	// independently, it can never leave a fresh Entry paired with stale or
	// absent Findings. A write failure is ignored rather than failing the
	// scan: caching is strictly a performance optimization, never a
	// correctness requirement.
	_ = s.findingCache.PutRecord(cache.Entry{FilePath: entry.Path, SHA256: contentHash}, fileFindings)

	return fileFindings, diags
}

// loadOrBuildIR returns the IR for path, preferring the AST cache over a
// fresh parse when contentHash matches a stored entry. A corrupted or
// unusable AST cache entry (bad JSON, a schema mismatch that fails to
// rebuild, etc.) degrades to a fresh parse rather than failing the file -
// the AST cache is a performance optimization, never a correctness
// requirement.
func (s *SASTScanner) loadOrBuildIR(ctx context.Context, path string, lang core.Language, source []byte, contentHash string) (*ir.IRFile, []string, error) {
	if data, ok := s.astCache.GetIR(path, contentHash); ok {
		if irFile, ok := decodeCachedIR(data, lang, path); ok {
			return irFile, nil, nil
		}
		// Corrupted/incompatible cache entry: fall through to a fresh parse.
	}

	irFile, warnings, err := s.buildIR(ctx, path, lang, source)
	if err != nil {
		return nil, warnings, err
	}

	// Write-through to the AST cache. A write failure is ignored rather than
	// failing the scan, for the same reason as the finding-cache write above.
	if data, ok := encodeIR(irFile); ok {
		_ = s.astCache.SetIR(path, contentHash, data)
	}

	return irFile, warnings, nil
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
