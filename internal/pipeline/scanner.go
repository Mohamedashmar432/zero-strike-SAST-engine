package pipeline

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"

	"github.com/zerostrike/scanner/internal/core"
	"github.com/zerostrike/scanner/internal/findings"
	"github.com/zerostrike/scanner/internal/langreg"
	"github.com/zerostrike/scanner/internal/rules"
	"github.com/zerostrike/scanner/internal/scanner"
	"github.com/zerostrike/scanner/internal/scanner/sast"
	scascan "github.com/zerostrike/scanner/internal/scanner/sca"
	"github.com/zerostrike/scanner/internal/scanner/secrets"
	"github.com/zerostrike/scanner/internal/walker"
)

// ScanResult holds the results of a completed scan.
type ScanResult struct {
	Findings     []core.Finding
	Diagnostics  []scanDiagnostic
	FilesScanned int
	FilesSkipped int
	Suppressed   int // findings filtered by allowlist
}

type scanDiagnostic struct {
	File    string
	Message string
}

// ScanPipeline orchestrates the full scan lifecycle.
type ScanPipeline struct {
	config    ScanConfig
	walker    walker.Walker
	scanners  []scanner.Scanner
	collector findings.Collector
	dedup     findings.Deduplicator
	allowList *findings.AllowList
}

// New creates a ScanPipeline. Returns an error if rules fail to load or
// validate, or if an explicitly requested language has no registered parser
// (fail fast at startup instead of erroring per file mid-scan).
func New(cfg ScanConfig) (*ScanPipeline, error) {
	for _, lang := range cfg.Languages {
		if _, ok := langreg.Get(lang); !ok {
			return nil, fmt.Errorf("pipeline: unsupported language %s: no parser registered (CGo-less builds register no parsers)", lang)
		}
	}

	allRules, err := loadAllRules(cfg)
	if err != nil {
		return nil, fmt.Errorf("pipeline: load rules: %w", err)
	}

	v := rules.NewValidator()
	for _, r := range allRules {
		if errs := v.Validate(r); len(errs) > 0 {
			return nil, fmt.Errorf("pipeline: invalid rule %s: %v", r.ID, errs)
		}
	}

	var scanners []scanner.Scanner
	scanners = append(scanners, sast.New(allRules, cfg.RootPath))
	if cfg.EnableSecrets {
		scanners = append(scanners, secrets.New())
	}
	if cfg.EnableSCA {
		onError := cfg.SCAOnError
		if onError == "" {
			onError = "warn"
		}
		scanners = append(scanners, scascan.New(onError))
	}

	// Load allowlist: explicit path, or auto-discover .zs-allow.yaml at root.
	var al *findings.AllowList
	allowPath := cfg.AllowFile
	if allowPath == "" {
		allowPath = filepath.Join(cfg.RootPath, ".zs-allow.yaml")
	}
	if _, statErr := os.Stat(allowPath); statErr == nil {
		al, err = findings.LoadAllowList(allowPath)
		if err != nil {
			return nil, fmt.Errorf("pipeline: load allowlist: %w", err)
		}
	}

	return &ScanPipeline{
		config:    cfg,
		walker:    walker.NewWalker(&walker.Options{ExcludeDirs: cfg.ExcludeDirs}),
		scanners:  scanners,
		collector: findings.NewCollector(),
		dedup:     findings.NewDeduplicator(),
		allowList: al,
	}, nil
}

// loadAllRules loads rules from all known language dirs (embedded or custom).
func loadAllRules(cfg ScanConfig) ([]*rules.Rule, error) {
	loader := rules.NewLoader(rulesFS(cfg))
	if cfg.RulesDir != "" {
		return loader.LoadDir(".")
	}
	var all []*rules.Rule
	for _, dir := range rules.RuleDirs {
		rs, err := loader.LoadDir(dir)
		if err != nil {
			return nil, fmt.Errorf("load rules from %s: %w", dir, err)
		}
		all = append(all, rs...)
	}
	return all, nil
}

// rulesFS returns the fs.FS to load rules from.
func rulesFS(cfg ScanConfig) fs.FS {
	if cfg.RulesDir != "" {
		return os.DirFS(cfg.RulesDir)
	}
	return rules.EmbeddedFS
}

// Run executes the scan and returns results.
func (p *ScanPipeline) Run(ctx context.Context) (*ScanResult, error) {
	fileCh, errCh := p.walker.Walk(p.config.RootPath)

	var allFiles []walker.FileEntry
	for entry := range fileCh {
		allFiles = append(allFiles, entry)
	}
	if err := <-errCh; err != nil {
		return nil, fmt.Errorf("walk failed: %w", err)
	}

	var result ScanResult
	result.FilesScanned = len(allFiles)

	workers := p.config.WorkerCount
	if workers == 0 {
		workers = runtime.NumCPU()
	}

	if workers == 1 || len(p.scanners) <= 1 {
		for _, sc := range p.scanners {
			var accepted []walker.FileEntry
			for _, f := range allFiles {
				if sc.Accepts(f) {
					accepted = append(accepted, f)
				}
			}
			scanFindings, diags, err := sc.Scan(ctx, accepted)
			if err != nil {
				return nil, fmt.Errorf("scanner %s: %w", sc.Name(), err)
			}
			p.collector.Add(scanFindings)
			for _, d := range diags {
				loc := ""
				if d.Location != nil {
					loc = d.Location.File
				}
				result.Diagnostics = append(result.Diagnostics, scanDiagnostic{File: loc, Message: d.Message})
			}
		}
	} else {
		// ponytail: run all scanners concurrently; goroutines = len(scanners) ≤ 3
		type scannerResult struct {
			name     string
			findings []core.Finding
			diags    []scanDiagnostic
			err      error
		}
		ch := make(chan scannerResult, len(p.scanners))
		for _, sc := range p.scanners {
			sc := sc
			go func() {
				var accepted []walker.FileEntry
				for _, f := range allFiles {
					if sc.Accepts(f) {
						accepted = append(accepted, f)
					}
				}
				scanFindings, diags, err := sc.Scan(ctx, accepted)
				sr := scannerResult{name: sc.Name(), findings: scanFindings, err: err}
				if err == nil {
					for _, d := range diags {
						loc := ""
						if d.Location != nil {
							loc = d.Location.File
						}
						sr.diags = append(sr.diags, scanDiagnostic{File: loc, Message: d.Message})
					}
				}
				ch <- sr
			}()
		}
		for range len(p.scanners) {
			sr := <-ch
			if sr.err != nil {
				return nil, fmt.Errorf("scanner %s: %w", sr.name, sr.err)
			}
			p.collector.Add(sr.findings)
			result.Diagnostics = append(result.Diagnostics, sr.diags...)
		}
	}

	all := p.dedup.Deduplicate(p.collector.All())

	if p.allowList != nil {
		kept := all[:0]
		for _, f := range all {
			if p.allowList.Suppressed(f) {
				result.Suppressed++
			} else {
				kept = append(kept, f)
			}
		}
		all = kept
	}

	result.Findings = all
	return &result, nil
}
