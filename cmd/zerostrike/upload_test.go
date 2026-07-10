// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/zerostrike/scanner/internal/portal"
)

func TestUploadCmd_SuccessFlow(t *testing.T) {
	var createCalls, uploadCalls atomic.Int32
	var gotUploadBody []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/scans":
			createCalls.Add(1)
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(portal.CreateScanResponse{ScanID: "scan_42", Status: "pending"})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/scans/scan_42/upload/json":
			uploadCalls.Add(1)
			buf := make([]byte, r.ContentLength)
			r.Body.Read(buf)
			gotUploadBody = buf
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
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
