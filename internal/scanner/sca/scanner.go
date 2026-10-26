package sca

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/analyzer"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/findings"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/walker"
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
	// AssetData entries are for the secrets scanner only (FileEntry.AssetData).
	if entry.AssetData {
		return false
	}
	base := filepath.Base(entry.Path)
	return base == "package-lock.json" ||
		base == "package.json" ||
		base == "yarn.lock" ||
		base == "pnpm-lock.yaml" ||
		base == "Pipfile.lock" ||
		base == "go.mod" ||
		base == "pom.xml" ||
		(strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt")) ||
		base == "packages.lock.json" ||
		base == "Directory.Packages.props" ||
		base == "Directory.Build.props" ||
		strings.EqualFold(base, "packages.config") ||
		isDotnetProject(base)
}

func (s *SCAScanner) Scan(ctx context.Context, files []walker.FileEntry) ([]core.Finding, []analyzer.Diagnostic, error) {
	var deps []Dependency
	var diags []analyzer.Diagnostic
	locked, nugetLocked := lockedDirs(files)
	for _, f := range files {
		// package.json holds ranges ("^4.17.15"), not installed versions; next to a lockfile it
		// would report the range's floor as installed and flag vulnerabilities the lock already fixed.
		if filepath.Base(f.Path) == "package.json" && locked[filepath.Dir(f.Path)] {
			continue
		}
		// Same for .NET: packages.lock.json holds the resolved versions (transitive included), the
		// project file only the requested ones.
		if isDotnetProject(filepath.Base(f.Path)) && nugetLocked[filepath.Dir(f.Path)] {
			continue
		}
		data, err := os.ReadFile(f.Path)
		if err != nil {
			diags = append(diags, analyzer.Diagnostic{
				Severity: "warning",
				Message:  fmt.Sprintf("failed to read lockfile %s: %v", f.Path, err),
				Location: &core.Location{File: f.Path},
			})
			continue
		}
		fileDeps, err := parseLockFileWithErr(f.Path, data)
		if err != nil {
			diags = append(diags, analyzer.Diagnostic{
				Severity: "warning",
				Message:  fmt.Sprintf("failed to parse %s: %v", f.Path, err),
				Location: &core.Location{File: f.Path},
			})
		}
		deps = append(deps, fileDeps...)
	}
	findings, scanDiags, err := s.scanDeps(ctx, deduplicateDeps(deps))
	diags = append(diags, scanDiags...)
	return findings, diags, err
}

// lockedDirs returns the directories holding an npm-family lockfile and those holding a NuGet
// packages.lock.json.
func lockedDirs(files []walker.FileEntry) (npm, nuget map[string]bool) {
	npm, nuget = map[string]bool{}, map[string]bool{}
	for _, f := range files {
		switch filepath.Base(f.Path) {
		case "package-lock.json", "yarn.lock", "pnpm-lock.yaml":
			npm[filepath.Dir(f.Path)] = true
		case "packages.lock.json":
			nuget[filepath.Dir(f.Path)] = true
		}
	}
	return npm, nuget
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
