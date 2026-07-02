// SPDX-License-Identifier: Apache-2.0
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var version = "v0.9.0"

func main() {
	root := &cobra.Command{
		Use:     "zerostrike",
		Short:   "ZeroStrike — Multi-scanner SAST engine",
		Version: version,
	}
	root.AddCommand(scanCmd())
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
