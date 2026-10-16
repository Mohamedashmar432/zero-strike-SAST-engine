// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/portal"
)

func uploadCmdSuccessServer(t *testing.T, gotUploadBody *[]byte, createCalls, uploadCalls *atomic.Int32) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/scans":
			createCalls.Add(1)
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(portal.CreateScanResponse{
				ScanID: "scan_42", Status: "pending", ProjectID: "proj_1", ProjectName: "Demo",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/scans/scan_42/upload/json":
			uploadCalls.Add(1)
			buf := make([]byte, r.ContentLength)
			r.Body.Read(buf)
			*gotUploadBody = buf
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

// TestUploadCmd_SuccessFlow proves the deprecated --project-id flag is still
// silently accepted — old, already-committed CI YAML must keep working.
func TestUploadCmd_SuccessFlow(t *testing.T) {
	var createCalls, uploadCalls atomic.Int32
	var gotUploadBody []byte
	srv := uploadCmdSuccessServer(t, &gotUploadBody, &createCalls, &uploadCalls)
	defer srv.Close()

	reportPath := filepath.Join(t.TempDir(), "report.json")
	reportBytes := []byte(`{"ScanID":"local-uuid","Findings":[]}`)
	if err := os.WriteFile(reportPath, reportBytes, 0o644); err != nil {
		t.Fatalf("write temp report: %v", err)
	}

	cmd := uploadCmd()
	cmd.SetArgs([]string{
		"--report", reportPath,
		"--project-id", "proj_1",
		"--server", srv.URL,
		"--token", "zst_live_test",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("uploadCmd().Execute() returned error: %v", err)
	}

	if got := createCalls.Load(); got != 1 {
		t.Errorf("POST /api/v1/scans called %d times, want 1", got)
	}
	if got := uploadCalls.Load(); got != 1 {
		t.Errorf("POST .../upload/json called %d times, want 1", got)
	}
	if string(gotUploadBody) != string(reportBytes) {
		t.Errorf("uploaded body = %q, want %q (upload must pass the file through unchanged)", gotUploadBody, reportBytes)
	}
}

// TestUploadCmd_SuccessFlow_NoProjectID proves the new, shorter invocation
// (no --project-id at all) works — the token alone resolves the project.
func TestUploadCmd_SuccessFlow_NoProjectID(t *testing.T) {
	var createCalls, uploadCalls atomic.Int32
	var gotUploadBody []byte
	srv := uploadCmdSuccessServer(t, &gotUploadBody, &createCalls, &uploadCalls)
	defer srv.Close()

	reportPath := filepath.Join(t.TempDir(), "report.json")
	reportBytes := []byte(`{"ScanID":"local-uuid","Findings":[]}`)
	if err := os.WriteFile(reportPath, reportBytes, 0o644); err != nil {
		t.Fatalf("write temp report: %v", err)
	}

	cmd := uploadCmd()
	cmd.SetArgs([]string{
		"--report", reportPath,
		"--server", srv.URL,
		"--token", "zst_live_test",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("uploadCmd().Execute() returned error: %v", err)
	}

	if got := createCalls.Load(); got != 1 {
		t.Errorf("POST /api/v1/scans called %d times, want 1", got)
	}
	if got := uploadCalls.Load(); got != 1 {
		t.Errorf("POST .../upload/json called %d times, want 1", got)
	}
}

// uploadCreateBodyServer records the decoded POST /api/v1/scans body.
func uploadCreateBodyServer(got *map[string]any) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/scans" {
			json.NewDecoder(r.Body).Decode(got)
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(portal.CreateScanResponse{ScanID: "scan_42", Status: "pending"})
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
}

func runUpload(t *testing.T, srvURL, repoDir string) {
	t.Helper()
	reportPath := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(reportPath, []byte(`{"Findings":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := uploadCmd()
	cmd.SetArgs([]string{"--report", reportPath, "--server", srvURL, "--token", "zst_live_test", "--repo-dir", repoDir})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("upload: %v", err)
	}
}

func TestUploadCmd_SendsGitMetadataFromRepoDir(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	clearCIEnv(t)
	dir := t.TempDir()
	for _, args := range [][]string{
		{"init", "-b", "feature-x"},
		{"-c", "user.email=t@t.com", "-c", "user.name=t", "commit", "--allow-empty", "-m", "init"},
		{"remote", "add", "origin", "https://tok@github.com/o/r.git"},
	} {
		c := exec.Command("git", args...)
		c.Dir = dir
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}

	var body map[string]any
	srv := uploadCreateBodyServer(&body)
	defer srv.Close()
	runUpload(t, srv.URL, dir)

	if body["repo_url"] != "https://github.com/o/r.git" {
		t.Errorf("repo_url = %v", body["repo_url"])
	}
	if body["branch"] != "feature-x" {
		t.Errorf("branch = %v", body["branch"])
	}
	if c, _ := body["git_commit"].(string); len(c) != 40 {
		t.Errorf("git_commit = %v", body["git_commit"])
	}
}

func TestUploadCmd_OmitsGitMetadataOutsideARepo(t *testing.T) {
	clearCIEnv(t)
	var body map[string]any
	srv := uploadCreateBodyServer(&body)
	defer srv.Close()
	runUpload(t, srv.URL, t.TempDir())

	for _, k := range []string{"repo_url", "branch", "git_commit"} {
		if _, ok := body[k]; ok {
			t.Errorf("%s should be omitted outside a git checkout, got %v", k, body[k])
		}
	}
}
