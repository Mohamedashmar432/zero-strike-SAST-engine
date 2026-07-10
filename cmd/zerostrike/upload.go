// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/portal"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/version"
)

// ponytail: upload is a pure pass-through of on-disk report bytes — it has
// no *report.Report to re-render, so unlike `scan`'s upload path it cannot
// force GroupByNone on a --group-by'd report (the grouped JSON shape drops
// the flat Findings array entirely). Reports meant for later `upload` must
// be generated with --group-by unset. Upgrade path if this bites someone:
// reparse-and-reflatten the grouped JSON here.
func uploadCmd() *cobra.Command {
	var (
		flagReportPath string
		flagHTMLPath   string
		flagProjectID  string
		flagServer     string
		flagToken      string
		flagScanLabel  string
	)

	cmd := &cobra.Command{
		Use:   "upload",
		Short: "Upload a previously generated report to the ZeroStrike portal",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()

			jsonBody, err := os.ReadFile(flagReportPath)
			if err != nil {
				return fmt.Errorf("read report: %w", err)
			}
			var htmlBody []byte
			if flagHTMLPath != "" {
				if htmlBody, err = os.ReadFile(flagHTMLPath); err != nil {
					return fmt.Errorf("read html report: %w", err)
				}
			}

			client := portal.New(flagServer, flagToken)
			hostname, _ := os.Hostname()
			resp, err := client.CreateScan(ctx, portal.CreateScanRequest{
				ProjectID:      flagProjectID,
				ScannerVersion: version.Version,
				Hostname:       hostname,
				ScanLabel:      flagScanLabel,
			})
			if err != nil {
				fmt.Fprintln(os.Stderr, describePortalError("create scan", err))
				os.Exit(2)
			}

			jsonErr := client.UploadJSON(ctx, resp.ScanID, jsonBody)
			if jsonErr != nil {
				fmt.Fprintln(os.Stderr, describePortalError("upload JSON report", jsonErr))
			}
			if len(htmlBody) > 0 {
				if err := client.UploadHTML(ctx, resp.ScanID, htmlBody); err != nil {
					fmt.Fprintf(os.Stderr, "warning: HTML upload failed: %v\n", err)
				}
			}

			if code := decideExitCode(0, jsonErr != nil); code != 0 {
				os.Exit(code)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&flagReportPath, "report", "", "path to a previously generated JSON report (required; must have been rendered with --group-by unset)")
	cmd.Flags().StringVar(&flagHTMLPath, "html", "", "path to a previously generated HTML report (optional)")
	cmd.Flags().StringVar(&flagProjectID, "project-id", "", "portal project ID (required)")
	cmd.Flags().StringVar(&flagServer, "server", "", "portal server base URL (required)")
	cmd.Flags().StringVar(&flagToken, "token", "", "portal project token (required)")
	cmd.Flags().StringVar(&flagScanLabel, "scan-label", "", "optional label for this scan")
	cmd.MarkFlagRequired("report")
	cmd.MarkFlagRequired("project-id")
	cmd.MarkFlagRequired("server")
	cmd.MarkFlagRequired("token")

	return cmd
}
