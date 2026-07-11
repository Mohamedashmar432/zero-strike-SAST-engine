// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os/exec"
	"strings"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/portal"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/report"
	jsonreport "github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/report/json"
)

// uploadFlagsError enforces that --server/--token are either both set
// (upload mode) or both unset (local-only) — a partial set almost
// certainly means a forgotten flag, not an intentional local-only scan.
// --project-id is no longer part of this check: the token alone resolves
// the project server-side (kept as a deprecated, accepted-but-ignored flag
// for backward compatibility with older committed CI pipeline YAML).
func uploadFlagsError(server, token string) error {
	set := 0
	for _, v := range []string{server, token} {
		if v != "" {
			set++
		}
	}
	if set != 0 && set != 2 {
		return fmt.Errorf("--server and --token must be set together (upload mode) or both omitted (local-only scan)")
	}
	return nil
}

// uploadEnabled reports whether upload mode is active.
func uploadEnabled(server, token string) bool {
	return server != "" && token != ""
}

// describePortalError formats a distinguishing, user-facing message for a
// portal API failure — an invalid/expired/revoked token reads very
// differently from "the server is down," even though both currently drive
// the same exit code.
func describePortalError(action string, err error) string {
	var httpErr *portal.HTTPError
	if errors.As(err, &httpErr) {
		if httpErr.StatusCode == http.StatusUnauthorized {
			return fmt.Sprintf("%s: invalid, expired, or revoked portal token (HTTP 401)", action)
		}
		return fmt.Sprintf("%s: portal returned HTTP %d: %s", action, httpErr.StatusCode, httpErr.Body)
	}
	return fmt.Sprintf("%s: %v", action, err)
}

// buildUploadJSON renders rep as JSON for portal upload, always ungrouped
// regardless of rep.GroupBy — the portal expects a flat Findings array;
// --group-by is a local reporting convenience only and must never change
// what the portal receives.
func buildUploadJSON(rep *report.Report) ([]byte, error) {
	uploadRep := *rep
	uploadRep.GroupBy = report.GroupByNone
	var buf bytes.Buffer
	if err := jsonreport.New().Render(&uploadRep, &buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// decideExitCode is scan's post-run exit-code precedence rule: an upload
// failure (2) takes precedence over findings-found (1). The local report
// file already shows findings either way, but an upload failure is the one
// outcome the user has no other way to notice, so it must not be masked.
func decideExitCode(findingsCount int, uploadFailed bool) int {
	if uploadFailed {
		return 2
	}
	if findingsCount > 0 {
		return 1
	}
	return 0
}

// gitInfo returns the current HEAD commit SHA and branch name for repoRoot.
// Best-effort only: any failure (git not on PATH, repoRoot not a git
// checkout, detached HEAD, etc.) yields empty strings, never an error — a
// scan must never fail just because it isn't run inside a git repository.
func gitInfo(ctx context.Context, repoRoot string) (commit, branch string) {
	commit = runGit(ctx, repoRoot, "rev-parse", "HEAD")
	branch = runGit(ctx, repoRoot, "rev-parse", "--abbrev-ref", "HEAD")
	if branch == "HEAD" {
		branch = "" // detached HEAD has no meaningful branch name
	}
	return commit, branch
}

func runGit(ctx context.Context, dir string, args ...string) string {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
