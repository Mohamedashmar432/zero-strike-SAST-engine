// SPDX-License-Identifier: Apache-2.0
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	// Blank imports register each language's IR builder with
	// internal/langreg (init()-time registration; CGo builds only —
	// under CGO_ENABLED=0 these packages are importable but empty).
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
	root := &cobra.Command{
		Use:     "zerostrike",
		Short:   "ZeroStrike — Multi-scanner SAST engine",
		Version: version.Version,
	}
	root.AddCommand(scanCmd())
	root.AddCommand(uploadCmd())
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
