package pipeline

import (
	"context"
	"fmt"
	"io/fs"
	"os"

	"github.com/zerostrike/scanner/internal/core"
	"github.com/zerostrike/scanner/internal/findings"
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
}

// New creates a ScanPipeline. Returns an error if rules fail to load or validate.
func New(cfg ScanConfig) (*ScanPipeline, error) {
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

	return &ScanPipeline{
		config:    cfg,
		walker:    walker.NewWalker(nil),
		scanners:  scanners,
		collector: findings.NewCollector(),
		dedup:     findings.NewDeduplicator(),
	}, nil
}

// loadAllRules loads rules from all known language dirs (embedded or custom).
func loadAllRules(cfg ScanConfig) ([]*rules.Rule, error) {
	loader := rules.NewLoader(rulesFS(cfg))
	if cfg.RulesDir != "" {
		return loader.LoadDir(".")
	}
	var all []*rules.Rule
	for _, dir := range []string{"data/python", "data/js"} {
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

	result.Findings = p.dedup.Deduplicate(p.collector.All())
	return &result, nil
}
