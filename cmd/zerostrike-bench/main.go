// SPDX-License-Identifier: Apache-2.0

// Command zerostrike-bench scores a scan run against the labeled corpus in
// benchmark/corpus/, computing TP/FP/FN/precision/recall instead of
// prose-based QA. Exits non-zero if recall/false-positive thresholds are
// violated, so it can gate CI the same way `zerostrike scan`'s exit code does.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/zerostrike/scanner/internal/benchmark"

	// Blank imports register each language's IR builder with
	// internal/langreg — same requirement as cmd/zerostrike/main.go.
	_ "github.com/zerostrike/scanner/internal/parser/csharp"
	_ "github.com/zerostrike/scanner/internal/parser/golang"
	_ "github.com/zerostrike/scanner/internal/parser/java"
	_ "github.com/zerostrike/scanner/internal/parser/javascript"
	_ "github.com/zerostrike/scanner/internal/parser/php"
	_ "github.com/zerostrike/scanner/internal/parser/python"
	_ "github.com/zerostrike/scanner/internal/parser/typescript"
	"github.com/zerostrike/scanner/internal/version"
)

func main() {
	var (
		corpusRoot   string
		minRecall    float64
		maxFP        int
		jsonOut      string
		mdOut        string
		enableGraphs bool
	)
	flag.StringVar(&corpusRoot, "corpus", "benchmark/corpus", "path to the benchmark corpus root")
	flag.Float64Var(&minRecall, "min-recall", 0.90, "minimum overall recall required to pass")
	flag.IntVar(&maxFP, "max-fp", 0, "maximum false positives allowed on declared true-negative cases before failing")
	flag.StringVar(&jsonOut, "json-out", "", "write the JSON report to this path (\"\" = skip)")
	flag.StringVar(&mdOut, "md-out", "", "write the Markdown report to this path (\"\" = skip)")
	flag.BoolVar(&enableGraphs, "enable-graphs", false, "enable CFG/DFG-based path-sensitive taint reporting (Python only)")
	flag.Parse()

	dirs, err := benchmark.LoadCorpus(corpusRoot)
	if err != nil {
		fmt.Fprintln(os.Stderr, "zerostrike-bench:", err)
		os.Exit(2)
	}

	summary, err := benchmark.ScoreCorpus(context.Background(), dirs, enableGraphs)
	if err != nil {
		fmt.Fprintln(os.Stderr, "zerostrike-bench:", err)
		os.Exit(2)
	}

	fmt.Printf("TP=%d FP=%d FN=%d precision=%.2f%% recall=%.2f%%\n",
		summary.TP, summary.FP, summary.FN, summary.Precision()*100, summary.Recall()*100)

	if jsonOut != "" {
		data, err := summary.JSON()
		if err != nil {
			fmt.Fprintln(os.Stderr, "zerostrike-bench: render json:", err)
			os.Exit(2)
		}
		if err := os.WriteFile(jsonOut, data, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "zerostrike-bench: write json:", err)
			os.Exit(2)
		}
	}
	if mdOut != "" {
		if err := os.WriteFile(mdOut, []byte(summary.Markdown(version.Version)), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "zerostrike-bench: write markdown:", err)
			os.Exit(2)
		}
	}

	failed := false
	if summary.Recall() < minRecall {
		fmt.Fprintf(os.Stderr, "zerostrike-bench: recall %.2f%% below minimum %.2f%%\n", summary.Recall()*100, minRecall*100)
		failed = true
	}
	if summary.FP > maxFP {
		fmt.Fprintf(os.Stderr, "zerostrike-bench: false positives %d exceed maximum %d\n", summary.FP, maxFP)
		failed = true
	}
	if failed {
		os.Exit(1)
	}
}
