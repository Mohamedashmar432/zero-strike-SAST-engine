// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/zerostrike/scanner/internal/analyzer"
	"github.com/zerostrike/scanner/internal/core"
	"github.com/zerostrike/scanner/internal/pipeline"
	"github.com/zerostrike/scanner/internal/report"
	jsonreport "github.com/zerostrike/scanner/internal/report/json"
	sarifreport "github.com/zerostrike/scanner/internal/report/sarif"
)

func scanCmd() *cobra.Command {
	var (
		flagFormat    string
		flagOutput    string
		flagLang      []string
		flagRules     string
		flagNoCache   bool
		flagWorkers   int
		flagEnableSec bool
		flagEnableSCA bool
		flagSCAError  string
		flagAllowFile string
	)

	cmd := &cobra.Command{
		Use:   "scan <path>",
		Short: "Scan a directory for security issues",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			rootPath := args[0]

			// Parse languages
			var langs []core.Language
			for _, l := range flagLang {
				switch strings.ToLower(l) {
				case "python":
					langs = append(langs, core.LangPython)
				case "javascript", "js":
					langs = append(langs, core.LangJavaScript)
				case "typescript", "ts":
					langs = append(langs, core.LangTypeScript)
				case "csharp", "cs":
					langs = append(langs, core.LangCSharp)
				}
			}

			cfg := pipeline.ScanConfig{
				RootPath:      rootPath,
				Languages:     langs,
				OutputFormat:  flagFormat,
				OutputFile:    flagOutput,
				RulesDir:      flagRules,
				WorkerCount:   flagWorkers,
				NoCache:       flagNoCache,
				EnableSecrets: flagEnableSec,
				EnableSCA:     flagEnableSCA,
				SCAOnError:    flagSCAError,
				AllowFile:     flagAllowFile,
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
				ByScanner:     make(map[string]int),
				ByKind:        make(map[core.FindingKind]int),
			}

			// Aggregate by scanner / kind
			for _, f := range result.Findings {
				stats.ByScanner[string(f.Kind)]++
				stats.ByKind[f.Kind]++
				if f.Location.File != "" {
					// track by language
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

			absRoot, _ := filepath.Abs(rootPath)
			rep := &report.Report{
				ScannerVersion: "v0.5.0-pre",
				StartedAt:      start,
				Duration:       elapsed,
				RootPath:       absRoot,
				Findings:       result.Findings,
				Stats:          stats,
				Diagnostics:    diags,
			}

			// Select reporter
			var repObj report.Reporter
			switch flagFormat {
			case "sarif":
				repObj = sarifreport.New()
			default:
				repObj = jsonreport.New()
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
	cmd.Flags().StringVar(&flagSCAError, "sca-on-error", "warn", "SCA on network error: warn|fail")
	cmd.Flags().StringVar(&flagAllowFile, "allow-file", "", "path to allowlist YAML (default: <root>/.zs-allow.yaml)")

	return cmd
}
