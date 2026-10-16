// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os/exec"
	"strings"
	"testing"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/portal"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/report"
)

func TestUploadFlagsError(t *testing.T) {
	cases := []struct {
		name          string
		server, token string
		wantErr       bool
	}{
		{"all empty", "", "", false},
		{"all set", "s", "t", false},
		{"only server", "s", "", true},
		{"only token", "", "t", true},
	}
	for _, c := range cases {
		err := uploadFlagsError(c.server, c.token)
		if (err != nil) != c.wantErr {
			t.Errorf("%s: uploadFlagsError(%q,%q) error = %v, wantErr %v", c.name, c.server, c.token, err, c.wantErr)
		}
	}
}

func TestUploadEnabled(t *testing.T) {
	cases := []struct {
		name          string
		server, token string
		want          bool
	}{
		{"all empty", "", "", false},
		{"all set", "s", "t", true},
		{"partial", "s", "", false},
	}
	for _, c := range cases {
		if got := uploadEnabled(c.server, c.token); got != c.want {
			t.Errorf("%s: uploadEnabled(%q,%q) = %v, want %v", c.name, c.server, c.token, got, c.want)
		}
	}
}

func TestDescribePortalError_Unauthorized(t *testing.T) {
	err := &portal.HTTPError{StatusCode: http.StatusUnauthorized, URL: "http://x/api/v1/scans", Body: "nope"}
	got := describePortalError("create scan", err)
	if !strings.Contains(got, "401") || !strings.Contains(got, "revoked") {
		t.Errorf("describePortalError(401) = %q, want it to mention 401 and revoked/expired", got)
	}
}

func TestDescribePortalError_ServerError(t *testing.T) {
	err := &portal.HTTPError{StatusCode: http.StatusInternalServerError, URL: "http://x", Body: "boom"}
	got := describePortalError("upload JSON report", err)
	if !strings.Contains(got, "500") {
		t.Errorf("describePortalError(500) = %q, want it to mention 500", got)
	}
	if strings.Contains(got, "revoked") {
		t.Errorf("describePortalError(500) = %q, should not mention token revocation", got)
	}
}

func TestDescribePortalError_NetworkError(t *testing.T) {
	err := errors.New("dial tcp: connection refused")
	got := describePortalError("create scan", err)
	if !strings.Contains(got, "connection refused") {
		t.Errorf("describePortalError(network) = %q, want it to include the underlying error", got)
	}
}

func TestBuildUploadJSON_ForcesGroupByNone(t *testing.T) {
	rep := &report.Report{
		ScanID: "s1",
		GroupBy: report.GroupByRule,
		Findings: []core.Finding{
			{RuleID: "ZS-PY-001", Severity: core.SeverityHigh},
			{RuleID: "ZS-PY-002", Severity: core.SeverityLow},
		},
	}
	body, err := buildUploadJSON(rep)
	if err != nil {
		t.Fatalf("buildUploadJSON returned error: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("unmarshal upload body: %v", err)
	}
	if _, ok := doc["Groups"]; ok {
		t.Error("upload body has a Groups key — GroupBy was not forced to GroupByNone")
	}
	findings, ok := doc["Findings"].([]any)
	if !ok {
		t.Fatalf("upload body has no flat Findings array: %+v", doc)
	}
	if len(findings) != 2 {
		t.Errorf("len(Findings) = %d, want 2", len(findings))
	}
	// rep itself must be untouched (buildUploadJSON must not mutate the
	// caller's Report, since scan.go reuses rep for the local --output file).
	if rep.GroupBy != report.GroupByRule {
		t.Errorf("caller's rep.GroupBy mutated to %q, want unchanged GroupByRule", rep.GroupBy)
	}
}

func TestDecideExitCode(t *testing.T) {
	cases := []struct {
		findings int
		failed   bool
		want     int
	}{
		{0, false, 0},
		{3, false, 1},
		{0, true, 2},
		{3, true, 2},
	}
	for _, c := range cases {
		if got := decideExitCode(c.findings, c.failed); got != c.want {
			t.Errorf("decideExitCode(%d,%v) = %d, want %d", c.findings, c.failed, got, c.want)
		}
	}
}

func TestGitInfo_InGitRepo(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	dir := t.TempDir()
	run := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, out)
		}
	}
	run("init", "-b", "test-branch")
	run("-c", "user.email=test@test.com", "-c", "user.name=test", "commit", "--allow-empty", "-m", "init")

	clearCIEnv(t)
	t.Setenv("GITHUB_HEAD_REF", "from-env")
	commit, branch, _ := gitInfo(context.Background(), dir)
	if len(commit) != 40 {
		t.Errorf("commit = %q, want a 40-char SHA", commit)
	}
	if branch != "test-branch" {
		t.Errorf("branch = %q, want test-branch (local branch must beat env)", branch)
	}
}

// clearCIEnv blanks every CI variable gitInfo reads so tests don't inherit
// the developer's or the runner's environment.
func clearCIEnv(t *testing.T) {
	t.Helper()
	for _, n := range append([]string{
		"GITHUB_SERVER_URL", "GITHUB_REPOSITORY", "BUILD_REPOSITORY_URI", "CI_PROJECT_URL",
	}, ciBranchEnvVars...) {
		t.Setenv(n, "")
	}
}

func TestGitInfo_NotAGitRepo(t *testing.T) {
	clearCIEnv(t)
	dir := t.TempDir()
	commit, branch, repoURL := gitInfo(context.Background(), dir)
	if commit != "" || branch != "" || repoURL != "" {
		t.Errorf("gitInfo(non-repo) = (%q,%q,%q), want all empty", commit, branch, repoURL)
	}
}

func detachedRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	dir := t.TempDir()
	run := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, out)
		}
	}
	run("init", "-b", "main")
	run("-c", "user.email=test@test.com", "-c", "user.name=test", "commit", "--allow-empty", "-m", "init")
	run("checkout", "--detach")
	return dir
}

func TestGitInfo_DetachedHeadUsesCIEnv(t *testing.T) {
	dir := detachedRepo(t)
	for _, name := range ciBranchEnvVars {
		t.Run(name, func(t *testing.T) {
			clearCIEnv(t)
			t.Setenv(name, "refs/heads/feature/x")
			_, branch, _ := gitInfo(context.Background(), dir)
			if branch != "feature/x" {
				t.Errorf("branch = %q, want feature/x", branch)
			}
		})
	}
	t.Run("none set", func(t *testing.T) {
		clearCIEnv(t)
		if _, branch, _ := gitInfo(context.Background(), dir); branch != "" {
			t.Errorf("branch = %q, want empty", branch)
		}
	})
	t.Run("order", func(t *testing.T) {
		clearCIEnv(t)
		t.Setenv("GITHUB_REF_NAME", "second")
		t.Setenv("GITHUB_HEAD_REF", "first")
		if _, branch, _ := gitInfo(context.Background(), dir); branch != "first" {
			t.Errorf("branch = %q, want first", branch)
		}
	})
}

func TestGitInfo_RepoURLFromRemoteAndEnv(t *testing.T) {
	dir := detachedRepo(t)

	clearCIEnv(t)
	t.Setenv("CI_PROJECT_URL", "https://gitlab.example.com/g/p")
	if _, _, u := gitInfo(context.Background(), dir); u != "https://gitlab.example.com/g/p" {
		t.Errorf("CI_PROJECT_URL fallback = %q", u)
	}
	t.Setenv("BUILD_REPOSITORY_URI", "https://dev.azure.com/org/proj/_git/repo")
	if _, _, u := gitInfo(context.Background(), dir); u != "https://dev.azure.com/org/proj/_git/repo" {
		t.Errorf("BUILD_REPOSITORY_URI fallback = %q", u)
	}
	t.Setenv("GITHUB_SERVER_URL", "https://github.com")
	t.Setenv("GITHUB_REPOSITORY", "org/repo")
	if _, _, u := gitInfo(context.Background(), dir); u != "https://github.com/org/repo" {
		t.Errorf("GITHUB_* fallback = %q", u)
	}

	cmd := exec.Command("git", "remote", "add", "origin", "https://user:tok@example.com/o/r.git?x=1")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git remote add: %v\n%s", err, out)
	}
	if _, _, u := gitInfo(context.Background(), dir); u != "https://example.com/o/r.git" {
		t.Errorf("origin remote should win and be sanitized, got %q", u)
	}
}

// Shared with backend/tests/test_repo_url_sanitize.py (sanitize_repo_url); keep in sync.
func TestSanitizeRepoURLVectors(t *testing.T) {
	legit := []string{
		"https://github.com/o/r",
		"https://github.com/o/r.git",
		"https://github.com/o/r/",
		"https://github.com/my-org/my-repo-name",
		"https://gitlab.com/g/sub/r",
		"https://gitlab.com/g/sub/deeper/r.git",
		"https://dev.azure.com/o/p/_git/r",
		"https://myorg.visualstudio.com/p/_git/r",
		"https://git.example.internal/team/sub/group/repo",
		"https://bitbucket.org/ws/repo",
	}
	bad := []string{
		"https://github.com/ghp_abcdefghijklmnopqrstuvwxyz0123456789/r",
		"https://github.com/o/github_pat_11ABCDEFG0abcdefghijkl",
		"https://github.com/x-access-token/r",
		"https://github.com/o/OAuth2",
		"https://gitlab.com/g/glpat-abcdefghijklmnopqrst/r",
		"https://gitlab.com/g/xoxb-123456789012-abcdef",
		"https://github.com/o/AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
		"https://github.com/o/r/extra",
		"https://github.com/o",
		"https://bitbucket.org/ws/repo/src",
		"https://dev.azure.com/o/p/r",
		"https://dev.azure.com/o/p/_git/r/extra",
		"https://myorg.visualstudio.com/p/r",
	}
	for _, in := range legit {
		if got := sanitizeRepoURL(in); got != in {
			t.Errorf("legit %q: got %q, want unchanged", in, got)
		}
	}
	for _, in := range bad {
		if got := sanitizeRepoURL(in); got != "" {
			t.Errorf("bad %q: got %q, want blank", in, got)
		}
	}
}

func TestSanitizeRepoURL(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"user and password", "https://user:secret@github.com/org/repo.git", "https://github.com/org/repo.git"},
		{"token-only username", "https://ghp_abc123@github.com/org/repo", "https://github.com/org/repo"},
		{"azure org@", "https://org@dev.azure.com/org/proj/_git/repo", "https://dev.azure.com/org/proj/_git/repo"},
		{"scp form", "git@github.com:org/repo.git", "https://github.com/org/repo.git"},
		{"query and fragment", "https://github.com/org/repo?token=abc#frag", "https://github.com/org/repo"},
		{"plain http", "http://git.local/org/repo", "http://git.local/org/repo"},
		{"empty", "", ""},
		{"whitespace", "  ", ""},
		{"ssh scheme", "ssh://git@github.com/org/repo.git", ""},
		{"file scheme", "file:///srv/repo", ""},
		{"local path", "/srv/repo", ""},
		{"no host", "https:///org/repo", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := sanitizeRepoURL(c.in); got != c.want {
				t.Errorf("sanitizeRepoURL(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}
