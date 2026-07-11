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

	commit, branch := gitInfo(context.Background(), dir)
	if len(commit) != 40 {
		t.Errorf("commit = %q, want a 40-char SHA", commit)
	}
	if branch != "test-branch" {
		t.Errorf("branch = %q, want test-branch", branch)
	}
}

func TestGitInfo_NotAGitRepo(t *testing.T) {
	dir := t.TempDir()
	commit, branch := gitInfo(context.Background(), dir)
	if commit != "" || branch != "" {
		t.Errorf("gitInfo(non-repo) = (%q,%q), want (\"\",\"\")", commit, branch)
	}
}
