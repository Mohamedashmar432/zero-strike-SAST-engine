// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/zerostrike/scanner/internal/analyzer"
	"github.com/zerostrike/scanner/internal/core"
	"github.com/zerostrike/scanner/internal/pipeline"
	"github.com/zerostrike/scanner/internal/report"
	htmlreport "github.com/zerostrike/scanner/internal/report/html"
	jsonreport "github.com/zerostrike/scanner/internal/report/json"
	sarifreport "github.com/zerostrike/scanner/internal/report/sarif"
)

// parseLanguages maps --lang flag values to core.Language. Unrecognized
// values are silently dropped here (pipeline.New validates the result
// against langreg and fails fast on anything actually unsupported) — but
// every langreg-registered language must have a case here, or its --lang
// flag silently falls back to auto-detect instead of restricting the scan.
func parseLanguages(raw []string) []core.Language {
	var langs []core.Language
	for _, l := range raw {
		switch strings.ToLower(l) {
		case "python":
			langs = append(langs, core.LangPython)
		case "javascript", "js":
			langs = append(langs, core.LangJavaScript)
		case "typescript", "ts":
			langs = append(langs, core.LangTypeScript)
		case "csharp", "cs":
			langs = append(langs, core.LangCSharp)
		case "go":
			langs = append(langs, core.LangGo)
		case "php":
			langs = append(langs, core.LangPHP)
		case "java":
			langs = append(langs, core.LangJava)
		}
	}
	return langs
}

// parseGroupBy maps a --group-by flag value to a report.GroupBy. It is
// validated up front (before the pipeline runs) so an invalid value fails
// fast instead of only surfacing after a potentially expensive scan.
func parseGroupBy(raw string) (report.GroupBy, error) {
	switch raw {
	case "", "none":
		return report.GroupByNone, nil
	case "file":
		return report.GroupByFile, nil
	case "rule":
		return report.GroupByRule, nil
	case "severity":
		return report.GroupBySeverity, nil
	case "language":
		return report.GroupByLanguage, nil
	default:
		return "", fmt.Errorf("unsupported --group-by %q (supported: file, rule, severity, language)", raw)
	}
}

func scanCmd() *cobra.Command {
	var (
		flagFormat      string
		flagOutput      string
		flagLang        []string
		flagRules       string
		flagNoCache     bool
		flagWorkers     int
		flagEnableSec   bool
		flagEnableSCA   bool
		flagEnableFW    bool
		flagSCAError    string
		flagAllowFile   string
		flagExcludeDirs []string
		flagGroupBy     string
	)

	cmd := &cobra.Command{
		Use:   "scan <path>",
		Short: "Scan a directory for security issues",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			rootPath := args[0]

			groupBy, err := parseGroupBy(flagGroupBy)
			if err != nil {
				return err
			}

			cfg := pipeline.ScanConfig{
				RootPath:              rootPath,
				Languages:             parseLanguages(flagLang),
				OutputFormat:          flagFormat,
				OutputFile:            flagOutput,
				RulesDir:              flagRules,
				WorkerCount:           flagWorkers,
				NoCache:               flagNoCache,
				EnableSecrets:         flagEnableSec,
				EnableSCA:             flagEnableSCA,
				EnableFrameworkChecks: flagEnableFW,
				SCAOnError:            flagSCAError,
				AllowFile:             flagAllowFile,
				ExcludeDirs:           flagExcludeDirs,
			}

			pipe, err := pipeline.New(cfg)
			if err != nil {
				return fmt.Errorf("pipeline.New: %w", err)
			}

			start := time.Now()
			result, err := pipe.Run(context.Background())
			elapsed := time.Since(start)
			if err != nil {
				return fmt.Errorf("scan failed: %w", err)
			}

			// Build stats
			stats := report.ScanStats{
				FilesScanned:  result.FilesScanned,
				FilesSkipped:  result.FilesSkipped,
				TotalFindings: len(result.Findings),
				Suppressed:    result.Suppressed,
				BySeverity:    make(map[core.Severity]int),
				ByLanguage:    make(map[core.Language]int),
				ByCategory:    make(map[string]int),
				ByScanner:     make(map[string]int),
				ByKind:        make(map[core.FindingKind]int),
			}

			for _, f := range result.Findings {
				stats.ByScanner[string(f.Kind)]++
				stats.ByKind[f.Kind]++
				stats.BySeverity[f.Severity]++
				if f.Language != "" && f.Language != core.LangUnknown {
					stats.ByLanguage[f.Language]++
				}
				if f.Category != "" {
					stats.ByCategory[f.Category]++
				}
			}

			// Build diagnostics
			var diags []analyzer.Diagnostic
			for _, d := range result.Diagnostics {
				diags = append(diags, analyzer.Diagnostic{
					Severity: "info",
					Message:  d.Message,
					Location: &core.Location{File: d.File},
				})
			}

			hostname, _ := os.Hostname()
			absRoot, _ := filepath.Abs(rootPath)
			rep := &report.Report{
				ScanID:         uuid.New().String(),
				ScannerVersion: version,
				StartedAt:      start,
				Duration:       elapsed,
				RootPath:       absRoot,
				Hostname:       hostname,
				Findings:       result.Findings,
				Stats:          stats,
				Diagnostics:    diags,
				GroupBy:        groupBy,
			}

			// Select reporter
			var repObj report.Reporter
			switch flagFormat {
			case "json", "":
				repObj = jsonreport.New()
			case "sarif":
				repObj = sarifreport.New()
			case "html":
				repObj = htmlreport.New()
			default:
				return fmt.Errorf("unsupported format %q (supported: json, sarif, html)", flagFormat)
			}

			var out *os.File
			if flagOutput != "" {
				var err error
				out, err = os.Create(flagOutput)
				if err != nil {
					return fmt.Errorf("create output: %w", err)
				}
				defer out.Close()
			} else {
				out = os.Stdout
			}

			if err := repObj.Render(rep, out); err != nil {
				return fmt.Errorf("render: %w", err)
			}

			// Exit code: 1 if findings exist, 0 otherwise
			if len(result.Findings) > 0 {
				os.Exit(1)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&flagFormat, "format", "f", "json", "output format: json|sarif|html")
	cmd.Flags().StringVarP(&flagOutput, "output", "o", "", "output file (default: stdout)")
	cmd.Flags().StringSliceVar(&flagLang, "lang", nil, "languages to scan (default: auto-detect)")
	cmd.Flags().StringVar(&flagRules, "rules", "", "rules directory (default: embedded)")
	cmd.Flags().BoolVar(&flagNoCache, "no-cache", false, "disable file cache")
	cmd.Flags().IntVar(&flagWorkers, "workers", 0, "worker count (default: NumCPU)")
	cmd.Flags().BoolVar(&flagEnableSec, "enable-secrets", false, "enable the Secrets scanner")
	cmd.Flags().BoolVar(&flagEnableSCA, "enable-sca", false, "enable the SCA/OSV dependency scanner")
	cmd.Flags().BoolVar(&flagEnableFW, "enable-framework-checks", false, "enable the framework misconfiguration scanner")
	cmd.Flags().StringVar(&flagSCAError, "sca-on-error", "warn", "SCA on network error: warn|fail")
	cmd.Flags().StringVar(&flagAllowFile, "allow-file", "", "path to allowlist YAML (default: <root>/.zs-allow.yaml)")
	cmd.Flags().StringSliceVar(&flagExcludeDirs, "exclude-dir", nil, "directory names to skip, e.g. --exclude-dir gen --exclude-dir templates")
	cmd.Flags().StringVar(&flagGroupBy, "group-by", "", "group findings in the report: file|rule|severity|language (default: no grouping for json, severity for html; ignored by sarif)")

	return cmd
}
