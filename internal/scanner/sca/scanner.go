package sca

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/zerostrike/scanner/internal/analyzer"
	"github.com/zerostrike/scanner/internal/core"
	"github.com/zerostrike/scanner/internal/findings"
	"github.com/zerostrike/scanner/internal/walker"
)

// SCAScanner detects vulnerable dependencies via the OSV database.
// Pure Go — no CGo, testable on Windows without gcc.
type SCAScanner struct {
	client  *osvClient
	onError string // "warn" | "fail"
}

// New returns an SCAScanner. onError controls behaviour on network failure.
func New(onError string) *SCAScanner {
	if onError == "" {
		onError = "warn"
	}
	return &SCAScanner{
		client:  newOSVClient(),
		onError: onError,
	}
}

func (s *SCAScanner) Name() string { return "sca" }

func (s *SCAScanner) Accepts(entry walker.FileEntry) bool {
	base := filepath.Base(entry.Path)
	return base == "package-lock.json" ||
		(strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt"))
}

func (s *SCAScanner) Scan(ctx context.Context, files []walker.FileEntry) ([]core.Finding, []analyzer.Diagnostic, error) {
	var deps []Dependency
	for _, f := range files {
		data, err := os.ReadFile(f.Path)
		if err != nil {
			continue
		}
		deps = append(deps, parseLockFile(f.Path, data)...)
	}
	return s.scanDeps(ctx, deduplicateDeps(deps))
}

// scanDeps runs the OSV query for a resolved dependency list.
// Extracted for testability without filesystem access.
func (s *SCAScanner) scanDeps(ctx context.Context, deps []Dependency) ([]core.Finding, []analyzer.Diagnostic, error) {
	if len(deps) == 0 {
		return nil, nil, nil
	}

	advisories, err := s.client.Match(ctx, deps)
	if err != nil {
		if s.onError == "fail" {
			return nil, nil, fmt.Errorf("sca: osv query: %w", err)
		}
		diag := analyzer.Diagnostic{
			Severity: "warning",
			Message:  "SCA scan skipped: " + err.Error(),
		}
		return nil, []analyzer.Diagnostic{diag}, nil
	}

	out := make([]core.Finding, 0, len(advisories))
	for _, adv := range advisories {
		msg := adv.Summary
		if msg == "" {
			msg = fmt.Sprintf("%s %s is vulnerable (%s)", adv.Dep.Package, adv.Dep.Version, adv.ID)
		}
		f := findings.BuildDependencyFinding(
			"ZS-SCA-001",
			"Vulnerable Dependency",
			msg,
			findings.DependencyInput{
				Ecosystem:        adv.Dep.Ecosystem,
				Package:          adv.Dep.Package,
				InstalledVersion: adv.Dep.Version,
				VulnerableRange:  adv.VulnerableRange,
				FixedVersion:     adv.FixedVersion,
				Manifest:         adv.Dep.Manifest,
				Direct:           adv.Dep.Direct,
			},
			adv.AliasIDs,
			adv.Severity,
			adv.Confidence,
		)
		out = append(out, f)
	}
	return out, nil, nil
}
