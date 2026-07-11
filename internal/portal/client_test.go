// SPDX-License-Identifier: Apache-2.0
package portal

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestCreateScan_Success(t *testing.T) {
	var gotAuth, gotMethod, gotPath string
	var gotBody CreateScanRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotMethod = r.Method
		gotPath = r.URL.Path
		json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(CreateScanResponse{
			ScanID: "abc123", Status: "pending", ProjectID: "proj_1", ProjectName: "Demo",
		})
	}))
	defer srv.Close()

	client := New(srv.URL, "zst_live_test")
	req := CreateScanRequest{
		ScannerVersion: "v0.22.0",
		Hostname:       "host1",
		GitCommit:      "deadbeef",
		Branch:         "main",
		ScanLabel:      "nightly",
	}
	resp, err := client.CreateScan(context.Background(), req)
	if err != nil {
		t.Fatalf("CreateScan returned error: %v", err)
	}
	if resp.ScanID != "abc123" {
		t.Errorf("ScanID = %q, want %q", resp.ScanID, "abc123")
	}
	if resp.ProjectID != "proj_1" || resp.ProjectName != "Demo" {
		t.Errorf("ProjectID/ProjectName = %q/%q, want proj_1/Demo", resp.ProjectID, resp.ProjectName)
	}
	if gotAuth != "Bearer zst_live_test" {
		t.Errorf("Authorization header = %q, want Bearer zst_live_test", gotAuth)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotPath != "/api/v1/scans" {
		t.Errorf("path = %q, want /api/v1/scans", gotPath)
	}
	if gotBody != req {
		t.Errorf("request body = %+v, want %+v", gotBody, req)
	}
}

func TestCreateScan_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("invalid token"))
	}))
	defer srv.Close()

	client := New(srv.URL, "bad-token")
	_, err := client.CreateScan(context.Background(), CreateScanRequest{})
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("expected *HTTPError, got %T: %v", err, err)
	}
	if httpErr.StatusCode != http.StatusUnauthorized {
		t.Errorf("StatusCode = %d, want 401", httpErr.StatusCode)
	}
}

func TestCreateScan_RetriesOnceOn500(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := requests.Add(1)
		if n == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(CreateScanResponse{ScanID: "retry-ok", Status: "pending"})
	}))
	defer srv.Close()

	client := New(srv.URL, "token")
	resp, err := client.CreateScan(context.Background(), CreateScanRequest{})
	if err != nil {
		t.Fatalf("CreateScan returned error: %v", err)
	}
	if resp.ScanID != "retry-ok" {
		t.Errorf("ScanID = %q, want retry-ok", resp.ScanID)
	}
	if got := requests.Load(); got != 2 {
		t.Errorf("server received %d requests, want 2", got)
	}
}

func TestCreateScan_500Persists(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	client := New(srv.URL, "token")
	_, err := client.CreateScan(context.Background(), CreateScanRequest{})
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("expected *HTTPError, got %T: %v", err, err)
	}
	if httpErr.StatusCode != http.StatusInternalServerError {
		t.Errorf("StatusCode = %d, want 500", httpErr.StatusCode)
	}
	if got := requests.Load(); got != 2 {
		t.Errorf("server received %d requests, want exactly 2 (initial + one retry)", got)
	}
}

func TestUploadJSON_Success(t *testing.T) {
	var gotPath, gotContentType string
	var gotBody []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotContentType = r.Header.Get("Content-Type")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := New(srv.URL, "token")
	payload := []byte(`{"ScanID":"x","Findings":[]}`)
	if err := client.UploadJSON(context.Background(), "scan_1", payload); err != nil {
		t.Fatalf("UploadJSON returned error: %v", err)
	}
	if gotPath != "/api/v1/scans/scan_1/upload/json" {
		t.Errorf("path = %q, want /api/v1/scans/scan_1/upload/json", gotPath)
	}
	if gotContentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotContentType)
	}
	if string(gotBody) != string(payload) {
		t.Errorf("body = %q, want %q", gotBody, payload)
	}
}

func TestUploadJSON_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	client := New(srv.URL, "token")
	err := client.UploadJSON(context.Background(), "scan_1", []byte(`{}`))
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
}

func TestUploadHTML_Success(t *testing.T) {
	var gotFieldName, gotFileContent string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			t.Errorf("ParseMultipartForm: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		for name, files := range r.MultipartForm.File {
			gotFieldName = name
			if len(files) > 0 {
				f, _ := files[0].Open()
				buf := make([]byte, files[0].Size)
				f.Read(buf)
				gotFileContent = string(buf)
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := New(srv.URL, "token")
	if err := client.UploadHTML(context.Background(), "scan_1", []byte("<html>report</html>")); err != nil {
		t.Fatalf("UploadHTML returned error: %v", err)
	}
	if gotFieldName != "file" {
		t.Errorf("multipart field name = %q, want %q", gotFieldName, "file")
	}
	if gotFileContent != "<html>report</html>" {
		t.Errorf("file content = %q, want %q", gotFileContent, "<html>report</html>")
	}
}

func TestUploadHTML_Failure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	client := New(srv.URL, "token")
	if err := client.UploadHTML(context.Background(), "scan_1", []byte("x")); err == nil {
		t.Fatal("expected an error, got nil")
	}
}

func TestUpdateStatus_Success(t *testing.T) {
	var gotMethod, gotPath string
	var gotBody statusUpdateRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := New(srv.URL, "token")
	if err := client.UpdateStatus(context.Background(), "scan_1", "failed", "pipeline exploded"); err != nil {
		t.Fatalf("UpdateStatus returned error: %v", err)
	}
	if gotMethod != http.MethodPut {
		t.Errorf("method = %q, want PUT", gotMethod)
	}
	if gotPath != "/api/v1/scans/scan_1/status" {
		t.Errorf("path = %q, want /api/v1/scans/scan_1/status", gotPath)
	}
	want := statusUpdateRequest{Status: "failed", ErrorMessage: "pipeline exploded"}
	if gotBody != want {
		t.Errorf("body = %+v, want %+v", gotBody, want)
	}
}
